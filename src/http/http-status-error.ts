export class HttpStatusError extends Error
{
    private static readonly MessagePrefix = "HTTP request failed with status ";
    private static readonly AtSeparator = " for ";
    private static readonly ErrorName = "HttpStatusError";

    public constructor(public readonly Status: number, url: string)
    {
        super(HttpStatusError.MessagePrefix + String(Status) + HttpStatusError.AtSeparator + HttpStatusError.Redact(url));
        this.name = HttpStatusError.ErrorName;
    }

    private static Redact(url: string): string
    {
        const parsed = new URL(url);
        return parsed.origin + parsed.pathname;
    }
}
