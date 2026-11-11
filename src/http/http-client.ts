export interface IHttpClient
{
    GetJson(url: string, bearer?: string): Promise<unknown>;
    PostForm(url: string, fields: ReadonlyMap<string, string>): Promise<unknown>;
}
