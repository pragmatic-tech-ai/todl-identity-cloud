export class HttpStatusError extends Error
{
    private static readonly MessagePrefix = "HTTP request failed with status ";
    private static readonly ErrorName = "HttpStatusError";

    public constructor(public readonly Status: number)
    {
        super(HttpStatusError.MessagePrefix + String(Status));
        this.name = HttpStatusError.ErrorName;
    }
}
