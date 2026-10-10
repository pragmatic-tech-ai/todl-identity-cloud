export interface IHttpClient
{
    GetJson(url: string): Promise<unknown>;
    PostForm(url: string, fields: ReadonlyMap<string, string>): Promise<unknown>;
}
