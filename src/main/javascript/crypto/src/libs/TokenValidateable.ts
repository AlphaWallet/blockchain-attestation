export interface TokenValidateable {
    /**
     * Returns true if the longer-term token that the object represent is valid.
     */
    checkTokenValidity(): boolean;
}
