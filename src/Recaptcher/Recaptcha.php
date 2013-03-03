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
     * @throws Exception
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
     * Calls an HTTP POST function to verify if the user's guess was correct
     *
     * @param string $remote_ip
     * @param string $challenge_val
     * @param string $response_val
     * @param array $extra_params an array of extra variables to post to the server
     * @throws Exception
     * @return bool
     */
    public function checkAnswer($remote_ip, $challenge_val, $response_val, array $extra_params = array())
    {
        if ($remote_ip == null || $remote_ip == '') {
            throw new Exception('You must pass the remote ip to reCAPTCHA');
        }

        // discard spam submissions
        if ($challenge_val == null || strlen($challenge_val) == 0 || $response_val == null || strlen($response_val) == 0) {
            throw new Exception('Please, enter reCAPTCHA');
        }

        $response = $this->httpPost(
            self::VERIFY_SERVER,
            '/recaptcha/api/verify',
            array(
                'privatekey' => $this->privateKey,
                'remoteip' => $remote_ip,
                'challenge' => $challenge_val,
                'response' => $response_val
            ) + $extra_params
        );

        $result = explode("\n", $response[1]);

        if (trim($result[0]) == 'true') {
            return true;
        } else {
            throw new Exception($result[1]);
        }
    }

    /**
     * Returns reCAPTCHA widget's HTML
     *
     * @param array $options Widget options
     * @return string Widget's HTML
     */
    public function getWidgetHtml(array $options = array())
    {
        $optionsHtml = '';
        if (!empty($options)) {
            $optionsHtml = '<script type="text/javascript">var RecaptchaOptions = ' . json_encode($options) . ';</script>';
        }

        return $optionsHtml . '<script type="text/javascript" src="' . $this->getChallengeUrl() . '"></script>
<noscript>
    <iframe src="' . $this->getIFrameUrl() . '" height="300" width="500"></iframe>
    <br/>
    <textarea name="'. $this->getChallengeField() .'" rows="3" cols="40"></textarea>
    <input type="hidden" name="'. $this->getResponseField() .'" value="manual_challenge"/>
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
     * Submits an HTTP POST
     *
     * @param string $host
     * @param string $path
     * @param array $data
     * @param int $port port
     * @throws \Recaptcher\Exception\Exception
     * @return array response
     */
    private function httpPost($host, $path, $data, $port = 80)
    {
        $qs = http_build_query($data);

        $request = "POST $path HTTP/1.0\r\n";
        $request .= "Host: $host\r\n";
        $request .= "Content-Type: application/x-www-form-urlencoded;\r\n";
        $request .= "Content-Length: " . strlen($qs) . "\r\n";
        $request .= "User-Agent: reCAPTCHA/PHP\r\n\r\n";
        $request .= $qs;

        $response = '';
        if (false == ($fs = @fsockopen($host, $port, $errno, $errstr, 10))) {
            throw new Exception('Could not open socket on ' . $host . ':' . $port);
        }

        fwrite($fs, $request);

        while (!feof($fs)) {
            $response .= fgets($fs, 1160);
        } // One TCP-IP packet
        fclose($fs);
        $response = explode("\r\n\r\n", $response, 2);

        return $response;
    }
}
