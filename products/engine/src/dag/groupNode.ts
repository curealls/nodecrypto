/** Group 노드(`type: 'groupNode'`): 노드·Link·Link Box·Document를 담는 실행하지 않는 틀. */

import { DOCUMENT_BGS, DOCUMENT_SCALES, isDocumentNode, type DocumentBg, type DocumentScale } from './documentNode';
export const GROUP_NODE_TYPE = 'groupNode';
/** 노드 레지스트리의 숨김 정의 이름 (`data.nodeType`). 최상위 `type`과 다르다. */
export const GROUP_REGISTRY_TYPE = 'group';

export const GROUP_CAPTION_SIDES = ['top', 'bottom', 'left', 'right'] as const;
export type GroupCaptionSide = (typeof GROUP_CAPTION_SIDES)[number];
export const GROUP_BORDER_STYLES = ['dotted', 'dashed', 'solid'] as const;
export type GroupBorderStyle = (typeof GROUP_BORDER_STYLES)[number];

export const GROUP_DEFAULT_SIZE = { width: 640, height: 320 } as const;
/** 최대 크기는 두지 않는다. */
export const GROUP_MIN_SIZE = { width: 160, height: 96 } as const;

/** Caption band thickness per caption scale (px). */
export const GROUP_BAND: Record<DocumentScale, number> = { xs: 20, sm: 24, md: 32, lg: 40, xl: 56 };

export type GroupRect = { x: number; y: number; width: number; height: number };

/** The body (frame minus the caption band), in the same coordinates as `frame`. */
export function bodyOf(frame: GroupRect, side: GroupCaptionSide, band: number): GroupRect {
  const { x, y, width, height } = frame;
  if (side === 'top') return { x, y: y + band, width, height: height - band };
  if (side === 'bottom') return { x, y, width, height: height - band };
  if (side === 'left') return { x: x + band, y, width: width - band, height };
  return { x, y, width: width - band, height };
}

/** Inverse of bodyOf: the frame that puts `band` on `side` around this body. */
export function frameOf(body: GroupRect, side: GroupCaptionSide, band: number): GroupRect {
  const { x, y, width, height } = body;
  if (side === 'top') return { x, y: y - band, width, height: height + band };
  if (side === 'bottom') return { x, y, width, height: height + band };
  if (side === 'left') return { x: x - band, y, width: width + band, height };
  return { x, y, width: width + band, height };
}

export const isGroupNode = (n: any): boolean => n?.type === GROUP_NODE_TYPE;

/** Document와 Group: 실행·검증·노드 수·식별자 해시에서 빠지는 노드. */
export const isNonExecutingNode = (n: any): boolean => isDocumentNode(n) || isGroupNode(n);
export const withoutNonExecuting = <T>(nodes: T[]): T[] => nodes.filter((n) => !isNonExecutingNode(n));

const size = (v: unknown, min: number, fallback: number): number =>
  typeof v === 'number' && Number.isFinite(v) && v > 0 ? Math.max(min, v) : fallback;
const oneOf = <T extends string>(list: readonly T[], v: unknown): T | undefined => (list.includes(v as T) ? (v as T) : undefined);

/** 읽을 때 쓰는 보정: 모르는 값은 기본으로, 크기는 최소 이상으로. 경고는 내지 않는다. */
export function normalizeGroupData(data: any): {
  label?: string;
  width: number;
  height: number;
  captionSide: GroupCaptionSide;
  captionScale: DocumentScale;
  color?: DocumentBg;
  borderStyle: GroupBorderStyle;
  fill: boolean;
} {
  return {
    label: typeof data?.label === 'string' ? data.label : undefined,
    width: size(data?.width, GROUP_MIN_SIZE.width, GROUP_DEFAULT_SIZE.width),
    height: size(data?.height, GROUP_MIN_SIZE.height, GROUP_DEFAULT_SIZE.height),
    captionSide: oneOf(GROUP_CAPTION_SIDES, data?.captionSide) ?? 'top',
    captionScale: oneOf(DOCUMENT_SCALES, data?.captionScale) ?? 'md',
    // one color drives band, border and fill; files from before the merge had captionBg / borderColor
    color: oneOf(DOCUMENT_BGS, data?.color) ?? oneOf(DOCUMENT_BGS, data?.borderColor) ?? oneOf(DOCUMENT_BGS, data?.captionBg),
    borderStyle: oneOf(GROUP_BORDER_STYLES, data?.borderStyle) ?? 'dotted',
    fill: data?.fill === true,
  };
}
