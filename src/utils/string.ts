export const b64encode = (u8: Uint8Array) => btoa(String.fromCharCode(...u8));
export const b64decode = (s: string) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));

export const equalTimeCompare = (a: string, b: string) => {
  if (a.length !== b.length) {
    return false;
  }

  let diff = 0;
  for (let i = 0; i < a.length; i++) {
    diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }
  return diff === 0;
};
