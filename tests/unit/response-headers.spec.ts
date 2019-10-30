import {expect} from 'chai';
import 'mocha';
import {Pwned} from "../../src/utilities/pwned";
import 'cross-fetch/polyfill';

describe('Pwned Class', () => {
	it('should be able to check for pwns', async () => {
		expect(await Pwned.haveIBeenPwned('test')).to.greaterThan(0);
	});
});