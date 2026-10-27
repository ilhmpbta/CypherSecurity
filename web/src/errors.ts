const MESSAGES: Record<string, string> = {
  invalid_credentials: "Invalid username or password",
  username_taken: "That username is already taken",
  weak_password: "Password does not meet requirements",
  csrf_invalid: "Your session expired — please reload and try again",
  rate_limited: "Too many attempts — please wait a moment",
  unknown: "Something went wrong — please try again",
};

export function friendlyMessage(code: string): string {
  return MESSAGES[code] ?? MESSAGES.unknown;
}