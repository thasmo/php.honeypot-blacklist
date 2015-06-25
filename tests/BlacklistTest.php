<?php

use Thasmo\ProjectHoneypot\Blacklist;

require __DIR__ . '/../src/Blacklist.php';

class BlacklistTest extends PHPUnit_Framework_TestCase {

	/**
	 * @expectedException InvalidArgumentException
	 */
	public function testInvalidAddress() {
		$address = $this->invalidAddress();
		$key = $this->validKey();

		new Blacklist($address, $key);
	}

	/**
	 * @expectedException InvalidArgumentException
	 */
	public function testInvalidKey() {
		$address = $this->validAddress();
		$key = $this->invalidKey();

		new Blacklist($address, $key);
	}

	public function testValidateKey() {
		$validKey = $this->validKey();
		$invalidKey = $this->invalidKey();

		$this->assertTrue(Blacklist::validateKey($validKey));
		$this->assertFalse(Blacklist::validateKey($invalidKey));
		$this->assertFalse(Blacklist::validateKey(NULL));
	}

	public function testValidateAddress() {
		$validAddress = $this->validAddress();
		$invalidAddress = $this->invalidAddress();

		$this->assertTrue(Blacklist::validateAddress($validAddress));
		$this->assertFalse(Blacklist::validateAddress($invalidAddress));
		$this->assertFalse(Blacklist::validateAddress(NULL));
	}

	/**
	 * @expectedException InvalidArgumentException
	 */
	public function testDefaultKey() {
		$validKey = $this->validKey();
		$invalidKey = $this->invalidKey();

		# set/get valid key
		Blacklist::setDefaultKey($validKey);
		$this->assertEquals($validKey, Blacklist::getDefaultKey());

		# unset/get empty key
		Blacklist::unsetDefaultKey();
		$this->assertEmpty(Blacklist::getDefaultKey());

		# set invalid key
		Blacklist::setDefaultKey($invalidKey);
	}

	public function testQuery() {
		$dummy = $this->dummyBlacklistforQuery('127.1.2.3');

		$this->assertEquals([
			'activity' => 1,
			'threat' => 2,
			'type' => 3
		], $dummy->query());
	}

	private function validKey() {
		return 'abcdefghijkl';
	}

	private function invalidKey() {
		return '123';
	}

	private function validAddress() {
		return '127.0.0.1';
	}

	private function invalidAddress() {
		return '192.168.0.1';
	}

	private function dummyBlacklistforQuery($result) {
		$dummy = $this->getMockBuilder('Thasmo\ProjectHoneypot\Blacklist')
			->disableOriginalConstructor()
			->setMethods(['lookup'])
			->getMock();

		$dummy->method('lookup')
			->will($this->returnValue($result));

		return $dummy;
	}
}
