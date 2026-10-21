import { describe, it, expect } from 'vitest';
import { validateHexInput } from 'nodecrypto-engine/crypto/utils/hexValidation';

describe('Hex Value Validation Rules Tests', () => {
  it('유효한 16진수 문자열을 정상 검증해야 한다', () => {
    const res1 = validateHexInput('00112233445566778899aabbccddeeff');
    expect(res1.isValid).toBe(true);
    expect(res1.cleanHex).toBe('00112233445566778899aabbccddeeff');
    expect(res1.byteCount).toBe(16);
    expect(res1.error).toBeUndefined();

    // 대소문자 혼합
    const res2 = validateHexInput('0A1b2C3d4E5f');
    expect(res2.isValid).toBe(true);
    expect(res2.cleanHex).toBe('0A1b2C3d4E5f');
    expect(res2.byteCount).toBe(6);
  });

  it('공백문자(스페이스, 탭, 줄바꿈)가 포함되어 있어도 정상 검증해야 한다', () => {
    const inputWithSpaces = '  00 11 22 \n 33 \t 44 \r\n 55  ';
    const res = validateHexInput(inputWithSpaces);
    expect(res.isValid).toBe(true);
    expect(res.cleanHex).toBe('001122334455');
    expect(res.byteCount).toBe(6);
  });

  it('허용되지 않은 문자(0x 접두사, g-z, 특수문자 등)가 포함된 경우 오류여야 한다', () => {
    // 0x 접두사의 'x'
    const res1 = validateHexInput('0x001122');
    expect(res1.isValid).toBe(false);
    expect(res1.errorMsg?.key).toBe('errors:hex.invalidChars');
    expect(res1.error).toContain('x');

    // 알파벳 g-z
    const res2 = validateHexInput('0011gg');
    expect(res2.isValid).toBe(false);
    expect(res2.errorMsg?.key).toBe('errors:hex.invalidChars');
    expect(res2.error).toContain('g');

    // 특수문자 (-)
    const res3 = validateHexInput('00-11-22-33');
    expect(res3.isValid).toBe(false);
    expect(res3.errorMsg?.key).toBe('errors:hex.invalidChars');
  });

  it('공백문자를 제외한 문자 개수가 짝수가 아닌 경우(홀수) 오류여야 한다', () => {
    const res1 = validateHexInput('00112');
    expect(res1.isValid).toBe(false);
    expect(res1.errorMsg).toEqual({ key: 'errors:hex.oddLength', params: { count: 5 } });

    const res2 = validateHexInput('0 1 2');
    expect(res2.isValid).toBe(false);
    expect(res2.errorMsg).toEqual({ key: 'errors:hex.oddLength', params: { count: 3 } });
  });

  it('빈 값에 대한 allowEmpty 옵션이 올바르게 동작해야 한다', () => {
    // allowEmpty = false (기본값)
    const resEmptyDefault = validateHexInput('');
    expect(resEmptyDefault.isValid).toBe(false);
    expect(resEmptyDefault.errorMsg?.key).toBe('errors:hex.required');

    const resWhitespaceDefault = validateHexInput('   \n\t  ');
    expect(resWhitespaceDefault.isValid).toBe(false);

    // allowEmpty = true
    const resEmptyAllowed = validateHexInput('', { allowEmpty: true });
    expect(resEmptyAllowed.isValid).toBe(true);
    expect(resEmptyAllowed.cleanHex).toBe('');
    expect(resEmptyAllowed.byteCount).toBe(0);

    const resWhitespaceAllowed = validateHexInput('  \t\n ', { allowEmpty: true });
    expect(resWhitespaceAllowed.isValid).toBe(true);
  });
});
