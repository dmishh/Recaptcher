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

interface RecaptchaInterface
{
    /**
     * @return string
     */
    function getChallengeField();

    /**
     * @return string
     */
    function getResponseField();

    /**
     * @param array $options
     * @return string
     */
    function getWidgetHtml(array $options = array());

    /**
     * Verifies user's input
     *
     * @param string $remoteIp
     * @param string $challengeValue
     * @param string $responseValue
     * @param array $params
     * @return bool
     */
    function checkAnswer($remoteIp, $challengeValue, $responseValue, array $params = array());
}