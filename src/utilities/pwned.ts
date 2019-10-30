import {sha1} from "../sha1";

const PWNED_RANGE_API = 'https://api.pwnedpasswords.com/range/';

export class Pwned {

	/**
	 * @description
	 * Checks whether the passed password was found in the have i been pawned database or not.
	 * Returns the number of hits in the database.
	 * @param {string} pw a clear text representation of the password
	 * @return {number} number of pawn hits
	 */
	public static async haveIBeenPwned(pw: string): Promise<number> {
		const [first5HashCharacters, remainingCharacters] = this.hashAndSplitPassword(pw);

		const pwnedData = await this.getPwnedData(first5HashCharacters);
		const regexp = this.hashToRegExp(remainingCharacters);

		return this.matchToNumber(pwnedData.match(regexp));
	}

	/**
	 * @description
	 * Transforms the given RegExpMatchArray (or null) into a number expecting the first match to contain a number
	 * @param {RegExpMatchArray} match
	 * @return {number}
	 */
	private static matchToNumber(match: RegExpMatchArray | null): number {
		if (match === null) {
			return 0;
		}
		return +match[1];
	}

	/**
	 * @description
	 * Makes a api call to the pwned api with the given part of the hash and returns the data
	 * @param {string} first5CharactersOfSha1Hash
	 * @return {Promise<string>}
	 */
	private static async getPwnedData(first5CharactersOfSha1Hash: string) {
		const response = await fetch(PWNED_RANGE_API + first5CharactersOfSha1Hash);

		return response.text();
	}

	/**
	 * @description
	 * Returns a regular expression for the given last 35 characters of a sha-1 hash that then matches the number of pwns
	 * @param {string} last35CharactersOfSha1Hash
	 * @return {RegExp}
	 */
	private static hashToRegExp(last35CharactersOfSha1Hash: string): RegExp {
		return new RegExp(`${last35CharactersOfSha1Hash}:(\\d+)`, 'i');
	}

	/**
	 * @description
	 * First hashes the passed password with sha-1 and then splits the hash into two values by the first 5 characters.
	 * @param {string} pw
	 * @return {[string , string]}
	 */
	private static hashAndSplitPassword(pw: string): [string, string] {
		const match = sha1.hash(pw).match(/(.{5})(.*)/);
		if (match === null) {
			throw new Error('Hash could not be split! (this is not normal ...)');
		}
		return [match[1], match[2]];
	}
}