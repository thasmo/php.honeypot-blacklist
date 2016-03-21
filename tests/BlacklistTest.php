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

	public function testResult() {
		$dummy = $this->dummyBlacklistforQuery('127.1.2.3');

		$this->assertEquals([
			'activity' => 1,
			'threat' => 2,
			'type' => 3
		], $dummy->getResult());
	}

	public function testSearchEngineNames() {
		$dummy = $this->dummyBlacklistforQuery('127.0.0.0');
		$this->assertFalse($dummy->getName());

		$dummy = $this->dummyBlacklistforQuery('127.0.12.0');
		$this->assertFalse($dummy->getName());

		$dummy = $this->dummyBlacklistforQuery('127.0.1.0');
		$this->assertEquals('AltaVista', $dummy->getName());

		$dummy = $this->dummyBlacklistforQuery('127.0.2.0');
		$this->assertEquals('Ask', $dummy->getName());

		$dummy = $this->dummyBlacklistforQuery('127.0.3.0');
		$this->assertEquals('Baidu', $dummy->getName());

		$dummy = $this->dummyBlacklistforQuery('127.0.4.0');
		$this->assertEquals('Excite', $dummy->getName());

		$dummy = $this->dummyBlacklistforQuery('127.0.5.0');
		$this->assertEquals('Google', $dummy->getName());

		$dummy = $this->dummyBlacklistforQuery('127.0.6.0');
		$this->assertEquals('Looksmart', $dummy->getName());

		$dummy = $this->dummyBlacklistforQuery('127.0.7.0');
		$this->assertEquals('Lycos', $dummy->getName());

		$dummy = $this->dummyBlacklistforQuery('127.0.8.0');
		$this->assertEquals('MSN', $dummy->getName());

		$dummy = $this->dummyBlacklistforQuery('127.0.9.0');
		$this->assertEquals('Yahoo', $dummy->getName());

		$dummy = $this->dummyBlacklistforQuery('127.0.10.0');
		$this->assertEquals('Cuil', $dummy->getName());

		$dummy = $this->dummyBlacklistforQuery('127.0.11.0');
		$this->assertEquals('InfoSeek', $dummy->getName());
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
