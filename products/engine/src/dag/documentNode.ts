/** Document 노드(`type: 'documentNode'`): 포트가 없고 실행하지 않는 설명문서 노드 (workflow-spec.md §5.1). */

import { normalizeNote } from './nodeNote';

export const DOCUMENT_NODE_TYPE = 'documentNode';
/** 노드 레지스트리의 숨김 정의 이름 (`data.nodeType`). 최상위 `type`과 다르다. */
export const DOCUMENT_REGISTRY_TYPE = 'document';

export const DOCUMENT_SCALES = ['xs', 'sm', 'md', 'lg', 'xl'] as const;
export type DocumentScale = (typeof DOCUMENT_SCALES)[number];

export const DOCUMENT_BGS = ['yellow', 'green', 'blue', 'pink', 'purple', 'gray'] as const;
export type DocumentBg = (typeof DOCUMENT_BGS)[number];

export const DOCUMENT_DEFAULT_SIZE = { width: 320, height: 240 } as const;
export const DOCUMENT_MIN_SIZE = { width: 160, height: 80 } as const;
export const DOCUMENT_MAX_SIZE = { width: 2048, height: 2048 } as const;

export const isDocumentNode = (n: any): boolean => n?.type === DOCUMENT_NODE_TYPE;

/** 실행·검증·해시가 보는 노드에서 Document를 뺀다. */
export const withoutDocuments = <T>(nodes: T[]): T[] => nodes.filter((n) => !isDocumentNode(n));

/** 사용자가 조절한 카드 크기를 범위 안으로(격자 맞춤이면 격자 단위로). */
export const clampDocumentSize = (w: number, h: number, grid = 0) => {
  const q = (v: number, min: number, max: number) => Math.min(max, Math.max(min, grid ? Math.round(v / grid) * grid : Math.round(v)));
  return { width: q(w, DOCUMENT_MIN_SIZE.width, DOCUMENT_MAX_SIZE.width), height: q(h, DOCUMENT_MIN_SIZE.height, DOCUMENT_MAX_SIZE.height) };
};

const clamp = (v: unknown, min: number, max: number, fallback: number): number =>
  typeof v === 'number' && Number.isFinite(v) && v > 0 ? Math.min(max, Math.max(min, v)) : fallback;

/** 읽을 때 쓰는 보정: 잘못된 배율은 `md`, 크기는 범위 안으로, 본문은 `normalizeNote`. 경고는 내지 않는다. */
export function normalizeDocumentData(data: any): { label?: string; note?: string; scale: DocumentScale; bg?: DocumentBg; width: number; height: number } {
  return {
    label: typeof data?.label === 'string' ? data.label : undefined,
    note: normalizeNote(typeof data?.note === 'string' ? data.note : undefined),
    scale: DOCUMENT_SCALES.includes(data?.scale) ? data.scale : 'md',
    bg: DOCUMENT_BGS.includes(data?.bg) ? data.bg : undefined,
    width: clamp(data?.width, DOCUMENT_MIN_SIZE.width, DOCUMENT_MAX_SIZE.width, DOCUMENT_DEFAULT_SIZE.width),
    height: clamp(data?.height, DOCUMENT_MIN_SIZE.height, DOCUMENT_MAX_SIZE.height, DOCUMENT_DEFAULT_SIZE.height),
  };
}
