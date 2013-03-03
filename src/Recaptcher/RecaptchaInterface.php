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
     * Return challenge field name
     *
     * @return string
     */
    function getChallengeField();

    /**
     * Return response field name
     *
     * @return string
     */
    function getResponseField();

    /**
     * @param array $options
     * @return string
     */
    function getWidgetHtml(array $options = array());

    /**
     * @param string $remote_ip
     * @param string $challenge_val
     * @param string $response_val
     * @param array $extra_params
     * @return bool
     */
    function checkAnswer($remote_ip, $challenge_val, $response_val, array $extra_params = array());
}