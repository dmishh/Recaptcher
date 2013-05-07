<?php
/**
 * This file is part of the Recaptcher package.
 *
 * (c) Dmitriy Scherbina
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */
namespace Recaptcher;

use Recaptcher\Exception\Exception;
use Recaptcher\Exception\InvalidRecaptchaException;

class Recaptcha implements RecaptchaInterface
{
    const SERVER_URL = 'http://www.google.com/recaptcha/api';
    const SECURE_SERVER_URL = 'https://www.google.com/recaptcha/api';
    const JS_SERVER_URL = 'http://www.google.com/recaptcha/api/js/recaptcha_ajax.js';
    const VERIFY_SERVER = 'www.google.com';

    /**
     * @var string
     */
    private $publicKey;

    /**
     * @var string
     */
    private $privateKey;

    /**
     * @var boolean
     */
    private $useHttps;

    /**
     * @param string $publicKey
     * @param string $privateKey
     * @param bool $useHttps
     * @throws \Recaptcher\Exception\Exception
     */
    public function __construct($publicKey, $privateKey, $useHttps = false)
    {
        if (!$publicKey || !$privateKey) {
            throw new Exception('Please provide reCAPTCHA keys');
        }

        $this->publicKey = $publicKey;
        $this->privateKey = $privateKey;
        $this->useHttps = $useHttps;
    }

    /**
     * Sends HTTP POST to server to verify user's input
     *
     * @param string $remoteIp
     * @param string $challengeValue
     * @param string $responseValue
     * @param array $params an array of extra parameters to POST to the server
     * @throws \Recaptcher\Exception\Exception
     * @throws \Recaptcher\Exception\InvalidRecaptchaException
     * @return bool
     */
    public function checkAnswer($remoteIp, $challengeValue, $responseValue, array $params = array())
    {
        if (!$remoteIp) {
            throw new Exception('You must pass the remote ip to reCAPTCHA');
        }

        if (strlen($challengeValue) == 0 || strlen($responseValue) == 0) {
            throw new InvalidRecaptchaException('Please, enter reCAPTCHA');
        }

        $response = $this->httpPost(
            self::VERIFY_SERVER,
            '/recaptcha/api/verify',
            array(
                'privatekey' => $this->privateKey,
                'remoteip' => $remoteIp,
                'challenge' => $challengeValue,
                'response' => $responseValue
            ) + $params
        );

        $response = explode("\r\n\r\n", $response, 2);
        if (!isset($response[1])) {
            throw new Exception(sprintf('Invalid response from verify server (%s)', self::VERIFY_SERVER));
        }

        // https://developers.google.com/recaptcha/docs/verify
        $result = explode("\n", $response[1]);
        if (trim($result[0]) !== 'true') {
            throw new InvalidRecaptchaException($result[1]);
        }

        return true;
    }

    /**
     * Returns reCAPTCHA widget's HTML
     *
     * @param array $options widget options
     * @return string
     */
    public function getWidgetHtml(array $options = array())
    {
        if (!empty($options)) {
            $optionsHtml = '<script type="text/javascript">var RecaptchaOptions = ' . json_encode($options) . ';</script>';
        } else {
            $optionsHtml = '';
        }

        return $optionsHtml . '<script type="text/javascript" src="' . $this->getChallengeUrl() . '"></script>
<noscript>
    <iframe src="' . $this->getIFrameUrl() . '" height="300" width="500"></iframe>
    <br/>
    <textarea name="' . $this->getChallengeField() . '" rows="3" cols="40"></textarea>
    <input type="hidden" name="' . $this->getResponseField() . '" value="manual_challenge"/>
</noscript>';
    }

    /**
     * @return string
     */
    public function getChallengeField()
    {
        return 'recaptcha_challenge_field';
    }

    /**
     * @return string
     */
    public function getResponseField()
    {
        return 'recaptcha_response_field';
    }

    /**
     * @return string
     */
    private function getChallengeUrl()
    {
        return $this->getServerUrl() . '/challenge?k=' . $this->publicKey;
    }

    /**
     * @return string
     */
    private function getIFrameUrl()
    {
        return $this->getServerUrl() . '/noscript?k=' . $this->publicKey;
    }

    /**
     * @return string
     */
    private function getServerUrl()
    {
        return $this->useHttps ? self::SECURE_SERVER_URL : self::SERVER_URL;
    }

    /**
     * Sends an HTTP POST and returns response
     *
     * @param string $host
     * @param string $path
     * @param array $data
     * @param int $port
     * @throws \Recaptcher\Exception\Exception
     * @return array
     */
    private function httpPost($host, $path, $data, $port = 80)
    {
        $queryString = http_build_query($data);

        $request = "POST $path HTTP/1.0\r\n" .
            "Host: $host\r\n" .
            "Content-Type: application/x-www-form-urlencoded;\r\n" .
            "Content-Length: " . strlen($queryString) . "\r\n" .
            "User-Agent: reCAPTCHA/PHP\r\n\r\n" .
            $queryString;

        $response = '';
        if (false == ($fs = @fsockopen($host, $port, $errno, $errstr, 5))) {
            throw new Exception('Could not open socket on ' . $host . ':' . $port);
        }

        fwrite($fs, $request);
        while (!feof($fs)) {
            $response .= fgets($fs, 1160);
        }
        fclose($fs);

        return $response;
    }
}
