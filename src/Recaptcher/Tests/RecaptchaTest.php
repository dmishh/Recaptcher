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
        new Recaptcha('', '123');
    }

    /**
     * @expectedException \Recaptcher\Exception\Exception
     */
    public function testConstructorWithEmptyPrivateKey()
    {
        new Recaptcha('123', '');
    }

    public function testConstructorWithValidKeys()
    {
        $this->assertInstanceOf('\Recaptcher\Recaptcha', new Recaptcha('123', '321'));
    }

    public function testGetChallengeField()
    {
        $recaptcha = new Recaptcha('123', '321');
        $this->assertEquals('recaptcha_challenge_field', $recaptcha->getChallengeField());
    }

    public function testGetResponseField()
    {
        $recaptcha = new Recaptcha('123', '321');
        $this->assertEquals('recaptcha_response_field', $recaptcha->getResponseField());
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

    public function testCheckAnswerWithStubbedHttpQueryWhenUserInputIsValid()
    {
        $recaptcha = $this->getMock('\Recaptcher\Recaptcha', array('httpPost'), array('123', '321'));
        $recaptcha->expects($this->any())
                  ->method('httpPost')
                  ->will($this->returnValue("HTTP/1.1 200 OK\r\n\r\ntrue"));

        $this->assertTrue($recaptcha->checkAnswer('127.0.0.1', 'challenge_val', 'response_val'));
    }

    /**
     * @expectedException \Recaptcher\Exception\InvalidRecaptchaException
     */
    public function testCheckAnswerWithStubbedHttpQueryWhenUserInputIsInvalid()
    {
        $recaptcha = $this->getMock('\Recaptcher\Recaptcha', array('httpPost'), array('123', '321'));
        $recaptcha->expects($this->any())
                  ->method('httpPost')
                  ->will($this->returnValue("HTTP/1.1 200 OK\r\n\r\nfalse\r\nInvalid captcha."));

        $recaptcha->checkAnswer('127.0.0.1', 'challenge_val', 'response_val');
    }

    /**
     * @expectedException \Recaptcher\Exception\Exception
     */
    public function testCheckAnswerWithStubbedHttpQueryWhenResponseIsInvalid()
    {
        $recaptcha = $this->getMock('\Recaptcher\Recaptcha', array('httpPost'), array('123', '321'));
        $recaptcha->expects($this->any())
                  ->method('httpPost')
                  ->will($this->returnValue("SOME STRANGE RESPONSE"));

        $recaptcha->checkAnswer('127.0.0.1', 'challenge_val', 'response_val');
    }

    /**
     * @covers \Recaptcher\Recaptcha::getServerUrl
     * @covers \Recaptcher\Recaptcha::getChallengeUrl
     * @covers \Recaptcher\Recaptcha::getIFrameUrl
     * @covers \Recaptcher\Recaptcha::getWidgetHtml
     */
    public function testGetWidgetHtml()
    {
        $recaptcha = new Recaptcha('123', '321');

        // options
        $options = array('theme' => 'red');
        $this->assertNotSame(
            false,
            strpos(
                $recaptcha->getWidgetHtml($options),
                '<script type="text/javascript">var RecaptchaOptions = ' . json_encode($options)
            )
        );

        // challenge url with lang
        $this->assertNotSame(
            false,
            strpos(
                $recaptcha->getWidgetHtml(array('lang' => 'ru')),
                '<script type="text/javascript" src="http://www.google.com/recaptcha/api/challenge?k=123&hl=ru"'
            )
        );

        // iframe url
        $this->assertNotSame(
            false,
            strpos(
                $recaptcha->getWidgetHtml(),
                '<iframe src="http://www.google.com/recaptcha/api/noscript?k=123"'
            )
        );
    }
}
