/**
 * Hexadecimal Value Validation Utilities
 *
 * [Hex Value 입력 규칙]
 * 1. 허용된 문자: 숫자(0-9), 알파벳(a-f, A-F), 공백문자(스페이스, 탭, 줄바꿈)
 * 2. 공백문자를 제외한 값에 해당하는 문자의 개수가 짝수가 아닌 경우 오류로 간주
 * 3. 노드의 실행이 아닌 값을 저장할 때 유효성을 확인해서 오류인 경우 저장 차단
 */

import { Msg, formatMsg, tmsg } from '../../messages';

export interface HexValidationResult {
  isValid: boolean;
  error?: string;
  /** Translatable form of `error` (the UI translates it; i18n.md §6.2) */
  errorMsg?: Msg;
  cleanHex: string;
  byteCount: number;
}

export interface HexValidationOptions {
  /**
   * 빈 값(공백만 있거나 길이가 0인 경우)을 허용할지 여부.
   * 기본값은 false (Hex 타입 값 필드는 바이트를 생성하므로 최소 1바이트 이상 필수).
   * Optional 필드(예: 마스크 등)인 경우 true로 지정 가능.
   */
  allowEmpty?: boolean;
  /**
   * 에러 메시지에 노출할 필드 레이블 (예: "Hex Value")
   */
  fieldLabel?: string;
}

const err = (errorMsg: Msg) => ({ error: formatMsg(errorMsg), errorMsg });

/**
 * 16진수 입력값에 대해 표준 규칙(허용 문자, 짝수 자릿수)을 검증합니다.
 */
export function validateHexInput(
  value: string | undefined | null,
  options: HexValidationOptions = {}
): HexValidationResult {
  const { allowEmpty = false, fieldLabel = 'Hex Value' } = options;
  const rawValue = value === undefined || value === null ? '' : String(value);

  // 1. 빈 값 처리
  const isAllWhitespace = rawValue.trim() === '';
  if (isAllWhitespace) {
    if (allowEmpty) {
      return {
        isValid: true,
        cleanHex: '',
        byteCount: 0,
      };
    }
    return {
      isValid: false,
      ...err(tmsg('errors:hex.required', { field: fieldLabel })),
      cleanHex: '',
      byteCount: 0,
    };
  }

  // 2. 규칙 1: 허용된 문자만 입력 가능 (숫자, a-f, A-F, 스페이스, 탭, 줄바꿈)
  const validCharsRegex = /^[0-9a-fA-F\s]*$/;
  if (!validCharsRegex.test(rawValue)) {
    // 허용되지 않은 문자 목록 추출 (중복 제거)
    const invalidChars = Array.from(new Set(rawValue.replace(/[0-9a-fA-F\s]/g, ''))).join(', ');
    return {
      isValid: false,
      ...err(tmsg('errors:hex.invalidChars', { chars: invalidChars })),
      cleanHex: rawValue.replace(/\s+/g, ''),
      byteCount: 0,
    };
  }

  // 3. 규칙 2: 공백문자를 제외한 값에 해당하는 문자의 개수가 짝수가 아닌 경우 오류로 간주
  const cleanHex = rawValue.replace(/\s+/g, '');
  if (cleanHex.length % 2 !== 0) {
    return {
      isValid: false,
      ...err(tmsg('errors:hex.oddLength', { count: cleanHex.length })),
      cleanHex,
      byteCount: Math.floor(cleanHex.length / 2),
    };
  }

  return {
    isValid: true,
    cleanHex,
    byteCount: cleanHex.length / 2,
  };
}
