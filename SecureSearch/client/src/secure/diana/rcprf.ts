import {
  assertLength,
  concatBytes,
} from "./bytes.js";
import {
  derivePrgKey,
  chacha20Prg,
  KEY_BYTES,
} from "./primitives.js";

export const DIANA_TREE_HEIGHT = 48;
export const DIANA_MAX_LEAF = (1n << BigInt(DIANA_TREE_HEIGHT - 1)) - 1n;
const SERIALIZED_HEADER_BYTES = 1 + 4;
const SERIALIZED_ELEMENT_INFO_BYTES = 1 + 8 + 8;
const MAX_SERIALIZED_ELEMENTS = DIANA_TREE_HEIGHT * 2;

export interface ConstrainedElement {
  readonly subtreeHeight: number;
  readonly minLeaf: bigint;
  readonly maxLeaf: bigint;
  readonly key: Uint8Array;
}

export interface ConstrainedRcpRf {
  readonly treeHeight: number;
  readonly elements: readonly ConstrainedElement[];
}

function subtreeLeafCount(subtreeHeight: number): bigint {
  return 1n << BigInt(subtreeHeight - 1);
}

function validateElement(element: ConstrainedElement): void {
  if (
    !Number.isInteger(element.subtreeHeight) ||
    element.subtreeHeight < 1 ||
    element.subtreeHeight > DIANA_TREE_HEIGHT
  ) {
    throw new RangeError("invalid constrained subtree height");
  }
  assertLength(element.key, KEY_BYTES, "constrained subtree key");
  if (
    element.minLeaf < 0n ||
    element.maxLeaf < element.minLeaf ||
    element.maxLeaf > DIANA_MAX_LEAF
  ) {
    throw new RangeError("invalid constrained leaf interval");
  }

  if (element.subtreeHeight === 1) {
    if (element.minLeaf !== element.maxLeaf) {
      throw new RangeError("leaf elements must identify exactly one leaf");
    }
    return;
  }

  const count = subtreeLeafCount(element.subtreeHeight);
  if (
    element.minLeaf % count !== 0n ||
    element.maxLeaf !== element.minLeaf + count - 1n
  ) {
    throw new RangeError("inner element must describe an aligned full subtree");
  }
}

function validateElements(elements: readonly ConstrainedElement[]): void {
  if (elements.length === 0 || elements.length > MAX_SERIALIZED_ELEMENTS) {
    throw new RangeError("invalid constrained element count");
  }
  let previousMax = -1n;
  for (const element of elements) {
    validateElement(element);
    if (element.minLeaf <= previousMax) {
      throw new RangeError("constrained elements must be ordered and disjoint");
    }
    previousMax = element.maxLeaf;
  }
}

export function createConstrainedRcpRf(
  rootKey: Uint8Array,
  minLeaf: bigint,
  maxLeaf: bigint,
): ConstrainedRcpRf {
  assertLength(rootKey, KEY_BYTES, "RCPRF root key");
  if (
    minLeaf < 0n ||
    maxLeaf < minLeaf ||
    maxLeaf > DIANA_MAX_LEAF
  ) {
    throw new RangeError("constrained range is outside the Diana tree");
  }
  if (minLeaf === 0n && maxLeaf === DIANA_MAX_LEAF) {
    throw new RangeError("OpenSSE does not constrain the complete tree");
  }

  const elements: ConstrainedElement[] = [];

  const visit = (
    nodeKey: Uint8Array,
    subtreeHeight: number,
    subtreeMin: bigint,
  ): void => {
    const subtreeMax =
      subtreeMin + subtreeLeafCount(subtreeHeight) - 1n;
    if (subtreeMax < minLeaf || subtreeMin > maxLeaf) {
      return;
    }

    if (minLeaf <= subtreeMin && subtreeMax <= maxLeaf) {
      elements.push({
        subtreeHeight,
        minLeaf: subtreeMin,
        maxLeaf: subtreeMax,
        key: nodeKey,
      });
      return;
    }

    if (subtreeHeight === 2) {
      for (const branch of [0, 1] as const) {
        const leaf = subtreeMin + BigInt(branch);
        if (minLeaf <= leaf && leaf <= maxLeaf) {
          elements.push({
            subtreeHeight: 1,
            minLeaf: leaf,
            maxLeaf: leaf,
            key: chacha20Prg(nodeKey, branch * KEY_BYTES, KEY_BYTES),
          });
        }
      }
      return;
    }

    if (subtreeHeight <= 1) {
      throw new Error("unexpected partial leaf in constrained-key generation");
    }

    const leftKey = derivePrgKey(nodeKey, 0);
    const rightKey = derivePrgKey(nodeKey, 1);
    visit(leftKey, subtreeHeight - 1, subtreeMin);
    visit(
      rightKey,
      subtreeHeight - 1,
      subtreeMin + subtreeLeafCount(subtreeHeight - 1),
    );
  };

  visit(rootKey, DIANA_TREE_HEIGHT, 0n);
  validateElements(elements);
  return { treeHeight: DIANA_TREE_HEIGHT, elements };
}

function evaluateElement(
  element: ConstrainedElement,
  leaf: bigint,
): Uint8Array {
  if (leaf < element.minLeaf || leaf > element.maxLeaf) {
    throw new RangeError("leaf is outside this constrained element");
  }
  if (element.subtreeHeight === 1) {
    return element.key.slice();
  }

  const pathLength = element.subtreeHeight - 1;
  const relativeLeaf = leaf - element.minLeaf;
  let nodeKey = element.key;
  for (let level = 0; level < pathLength; level++) {
    const bitPosition = BigInt(pathLength - level - 1);
    const branch = Number((relativeLeaf >> bitPosition) & 1n) as 0 | 1;
    const offset = branch * KEY_BYTES;
    if (level === pathLength - 1) {
      return chacha20Prg(nodeKey, offset, KEY_BYTES);
    }
    nodeKey = derivePrgKey(nodeKey, branch);
  }
  throw new Error("unreachable RCPRF evaluation state");
}

export function evaluateConstrained(
  constrained: ConstrainedRcpRf,
  leaf: bigint,
): Uint8Array {
  if (constrained.treeHeight !== DIANA_TREE_HEIGHT) {
    throw new RangeError("unsupported Diana RCPRF tree height");
  }
  if (leaf < 0n || leaf > DIANA_MAX_LEAF) {
    throw new RangeError("leaf is outside the Diana RCPRF tree");
  }
  for (const element of constrained.elements) {
    if (element.minLeaf <= leaf && leaf <= element.maxLeaf) {
      return evaluateElement(element, leaf);
    }
  }
  throw new RangeError("leaf is outside the constrained range");
}

export function evaluateConstrainedRange(
  constrained: ConstrainedRcpRf,
  minLeaf: bigint,
  maxLeaf: bigint,
): Array<{ leaf: bigint; value: Uint8Array }> {
  if (maxLeaf < minLeaf) {
    throw new RangeError("maximum leaf is smaller than minimum leaf");
  }
  if (minLeaf < 0n || maxLeaf > DIANA_MAX_LEAF) {
    throw new RangeError("requested range is outside the Diana tree");
  }
  const values: Array<{ leaf: bigint; value: Uint8Array }> = [];
  for (let leaf = minLeaf; leaf <= maxLeaf; leaf++) {
    values.push({ leaf, value: evaluateConstrained(constrained, leaf) });
  }
  return values;
}

export function serializeConstrained(
  constrained: ConstrainedRcpRf,
): Uint8Array {
  if (constrained.treeHeight !== DIANA_TREE_HEIGHT) {
    throw new RangeError("unsupported Diana RCPRF tree height");
  }
  validateElements(constrained.elements);
  const header = new Uint8Array(SERIALIZED_HEADER_BYTES);
  header[0] = constrained.treeHeight;
  new DataView(header.buffer).setUint32(
    1,
    constrained.elements.length,
    true,
  );

  const encodedElements = constrained.elements.map((element) => {
    const info = new Uint8Array(SERIALIZED_ELEMENT_INFO_BYTES);
    info[0] = element.subtreeHeight;
    const view = new DataView(info.buffer);
    view.setBigUint64(1, element.minLeaf, true);
    view.setBigUint64(9, element.maxLeaf, true);
    return concatBytes(info, element.key);
  });
  return concatBytes(header, ...encodedElements);
}

export function deserializeConstrained(
  serialized: Uint8Array,
): ConstrainedRcpRf {
  if (serialized.length < SERIALIZED_HEADER_BYTES) {
    throw new RangeError("constrained-key header is truncated");
  }
  const view = new DataView(
    serialized.buffer,
    serialized.byteOffset,
    serialized.byteLength,
  );
  const treeHeight = serialized[0]!;
  const elementCount = view.getUint32(1, true);
  if (
    treeHeight !== DIANA_TREE_HEIGHT ||
    elementCount === 0 ||
    elementCount > MAX_SERIALIZED_ELEMENTS
  ) {
    throw new RangeError("invalid constrained-key header");
  }
  const elementBytes = SERIALIZED_ELEMENT_INFO_BYTES + KEY_BYTES;
  const expectedLength =
    SERIALIZED_HEADER_BYTES + elementCount * elementBytes;
  if (serialized.length !== expectedLength) {
    throw new RangeError("constrained-key length does not match its header");
  }

  const elements: ConstrainedElement[] = [];
  let offset = SERIALIZED_HEADER_BYTES;
  for (let i = 0; i < elementCount; i++) {
    const info = new DataView(
      serialized.buffer,
      serialized.byteOffset + offset,
      SERIALIZED_ELEMENT_INFO_BYTES,
    );
    const subtreeHeight = serialized[offset]!;
    const minLeaf = info.getBigUint64(1, true);
    const maxLeaf = info.getBigUint64(9, true);
    offset += SERIALIZED_ELEMENT_INFO_BYTES;
    const key = serialized.slice(offset, offset + KEY_BYTES);
    offset += KEY_BYTES;
    elements.push({ subtreeHeight, minLeaf, maxLeaf, key });
  }
  validateElements(elements);
  return { treeHeight, elements };
}

export function assertConstrainedPrefix(
  constrained: ConstrainedRcpRf,
  addCount: number,
): void {
  if (!Number.isInteger(addCount) || addCount < 1 || addCount > 0xffff_ffff) {
    throw new RangeError("add_count must be a positive uint32");
  }
  let expectedMin = 0n;
  const expectedMax = BigInt(addCount - 1);
  for (const element of constrained.elements) {
    if (element.minLeaf !== expectedMin) {
      throw new RangeError("constrained key does not cover the expected prefix");
    }
    expectedMin = element.maxLeaf + 1n;
  }
  if (expectedMin !== expectedMax + 1n) {
    throw new RangeError("constrained key does not cover the expected prefix");
  }
}
