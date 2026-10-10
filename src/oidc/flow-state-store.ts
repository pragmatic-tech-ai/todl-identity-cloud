import type { OidcFlowState } from "./oidc-flow-state.js";

export interface IOidcFlowStateStore
{
    Put(state: OidcFlowState): Promise<void>;
    /** Single-use: removes the entry; returns null if absent or expired. */
    Take(state: string): Promise<OidcFlowState | null>;
}

export class InMemoryOidcFlowStateStore implements IOidcFlowStateStore
{
    private readonly states = new Map<string, OidcFlowState>();

    public constructor(private readonly now: () => Date = () => new Date())
    {
    }

    public async Put(state: OidcFlowState): Promise<void>
    {
        this.states.set(state.State, state);
    }

    public async Take(state: string): Promise<OidcFlowState | null>
    {
        const found = this.states.get(state);
        if (!found) return null;
        this.states.delete(state);
        if (this.now().getTime() >= found.ExpiresAt.getTime()) return null;
        return found;
    }

    /** Test-support only: non-consuming lookup. Deliberately NOT on IOidcFlowStateStore. */
    public Peek(state: string): OidcFlowState | null
    {
        return this.states.get(state) ?? null;
    }
}
