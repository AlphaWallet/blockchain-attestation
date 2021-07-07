export class UnpredictableNumberBundle {
  private _number: string;
  private _domain: string;
  private _expiration: bigint;

  constructor(number: string, domain: string, expiration: bigint) {
    this._number = number;
    this._domain = domain;
    this._expiration = expiration;
  }


  get number(): string {
    return this._number;
  }

  set number(value: string) {
    this._number = value;
  }

  get domain(): string {
    return this._domain;
  }

  set domain(value: string) {
    this._domain = value;
  }

  get expiration(): bigint {
    return this._expiration;
  }

  set expiration(value: bigint) {
    this._expiration = value;
  }
}
