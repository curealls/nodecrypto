/** 노드 메모(`data.note`) 규칙 (web ui-canvas-spec.md §20, authoring.md §2.2). 웹 편집과 초안 펼치기가 공유한다. */

/** 메모 길이 상한(글자 수). 파일 비대화를 막는다. */
export const NOTE_MAX_LENGTH = 20000;

/** 저장할 메모: 상한까지만 남기고, 공백뿐이면 `undefined`(필드를 두지 않는다) */
export function normalizeNote(raw: string | undefined | null): string | undefined {
  if (!raw || raw.trim() === '') return undefined;
  return raw.length > NOTE_MAX_LENGTH ? raw.slice(0, NOTE_MAX_LENGTH) : raw;
}
