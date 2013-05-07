<?php
/**
 * This file is part of the Recaptcher package.
 *
 * (c) Dmitriy Scherbina
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */
namespace Recaptcher\Tests;

use Recaptcher\Recaptcha;
use Recaptcher\Exception\Exception;
use Recaptcher\Exception\InvalidRecaptchaException;

class RecaptchaTest extends \PHPUnit_Framework_TestCase
{
    /**
     * @expectedException \Recaptcher\Exception\Exception
     */
    public function testConstructorWithEmptyPublicKey()
    {
        $recaptcha = new Recaptcha('', '123');
    }

    /**
     * @expectedException \Recaptcher\Exception\Exception
     */
    public function testConstructorWithEmptyPrivateKey()
    {
        $recaptcha = new Recaptcha('123', '');
    }

    public function testConstructorWithValidKeys()
    {
        $this->assertInstanceOf('\Recaptcher\Recaptcha', new Recaptcha('123', '321'));
    }

    /**
     * @expectedException \Recaptcher\Exception\Exception
     */
    public function testCheckAnswerWithWrongIp()
    {
        $recaptcha = new Recaptcha('123', '321');
        $recaptcha->checkAnswer('', 'challenge_val', 'response_val');
    }
 
    /**
     * @expectedException \Recaptcher\Exception\InvalidRecaptchaException
     */
    public function testCheckAnswerWithWrongChallengeValue()
    {
        $recaptcha = new Recaptcha('123', '321');
        $recaptcha->checkAnswer('127.0.0.1', '', 'response_val');
    }
 
    /**
     * @expectedException \Recaptcher\Exception\InvalidRecaptchaException
     */
    public function testCheckAnswerWithWrongResponseValue()
    {
        $recaptcha = new Recaptcha('123', '321');
        $recaptcha->checkAnswer('127.0.0.1', 'challenge_val', '');
    }
}
