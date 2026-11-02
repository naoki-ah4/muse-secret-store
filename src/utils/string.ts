
export const b64encode = (u8: Uint8Array) => btoa(String.fromCharCode(...u8))
export const b64decode = (s: string) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0))
