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
    function getWidgetHtml(array $options = array());
    function checkAnswer($remote_ip, $challenge_val, $response_val, $extra_params = array());
}