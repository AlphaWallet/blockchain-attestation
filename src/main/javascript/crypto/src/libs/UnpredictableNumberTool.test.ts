import {suite, test} from '@testdeck/mocha';
import {DEFAULT_VALIDITY_IN_MS, UnpredictableNumberTool} from "./UnpredictableNumberTool";
import {UnpredictableNumberBundle} from "./UnpredictableNumberBundle";
import {expect} from 'chai';


@suite
class UnpredictableNumberToolTest {

  static readonly DOMAIN: string = 'http://www.hotel-bogota.com';
  static readonly mocKey: Uint8Array = new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8]);

  @test 'should be valid unpredictable number'() {
    const unt: UnpredictableNumberTool = UnpredictableNumberToolTest.createDefaultUnt();
    expect(unt.domain).eq(UnpredictableNumberToolTest.DOMAIN);
    const un = unt.unpredictableNumberBundle;
    expect(unt.validateUnpredictableNumber(un.number, un.randomness, un.expiration)).true;
  }

  @test 'should throw error given invalid domain'() {
    expect(
        () => new UnpredictableNumberTool(UnpredictableNumberToolTest.mocKey, 'NotADomain', BigInt(0))
    ).throw('Domain is not a valid domain');
  }

  @test 'should be invalid unpredictable number given invalid expiration'() {
    const unt: UnpredictableNumberTool = UnpredictableNumberToolTest.createDefaultUnt();
    const un: UnpredictableNumberBundle = unt.unpredictableNumberBundle;
    un.expiration = BigInt(0);
    expect(unt.validateUnpredictableNumber(un.number, un.randomness, un.expiration)).false;
  }

  @test 'should be invalid unpredictable number given different domain'() {
    const unt: UnpredictableNumberTool = UnpredictableNumberToolTest.createDefaultUnt();
    const un = unt.unpredictableNumberBundle;
    const differentDomainUnt: UnpredictableNumberTool = new UnpredictableNumberTool(
        UnpredictableNumberToolTest.mocKey,
        'http://www.other-domain.com',
        DEFAULT_VALIDITY_IN_MS
    );
    expect(differentDomainUnt.validateUnpredictableNumber(un.number, un.randomness, un.expiration)).false;
  }

  @test 'should be invalid predictable number given different key'() {
    const unt: UnpredictableNumberTool = UnpredictableNumberToolTest.createDefaultUnt();
    const un = unt.unpredictableNumberBundle;
    const differentDomainUnt: UnpredictableNumberTool = new UnpredictableNumberTool(
        new Uint8Array([8, 7, 6, 5, 4, 3, 2, 1]),
        UnpredictableNumberToolTest.DOMAIN,
        DEFAULT_VALIDITY_IN_MS
    );
    expect(differentDomainUnt.validateUnpredictableNumber(un.number, un.randomness, un.expiration)).false;
  }

  private static createDefaultUnt(): UnpredictableNumberTool {
    return new UnpredictableNumberTool(
        UnpredictableNumberToolTest.mocKey,
        UnpredictableNumberToolTest.DOMAIN,
        DEFAULT_VALIDITY_IN_MS
    );
  }
}
