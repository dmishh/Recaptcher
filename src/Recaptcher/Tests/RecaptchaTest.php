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

class RecaptchaTest extends \PHPUnit_Framework_TestCase
{
    public function testConstructor()
    {
        try {
            $recaptcha = new Recaptcha('', '123');
            $this->fail('Public key must be provided');
        } catch (Exception $e) {
        }

        try {
            $recaptcha = new Recaptcha('123', '');
            $this->fail('Private key must be provided');
        } catch (Exception $e) {
        }

        $this->assertInstanceOf('\Recaptcher\Recaptcha', new Recaptcha('123', '321'));
    }
}