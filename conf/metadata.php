<?php

$meta['freqBorder'] = array('numeric', '_min' => 0);
$meta['confidenceBorder'] = array('numeric', '_min' => 0, '_max' => 100);
$meta['protectRegFreq'] = array('numeric', '_min' => -1);
$meta['protectRegConf'] = array('numeric', '_min' => -1, '_max' => 100);
$meta['preventNuisanceReg'] = array('numeric', '_min' => 0);
$meta['protectEditFreq'] = array('numeric', '_min' => -1);
$meta['protectEditConf'] = array('numeric', '_min' => -1, '_max' => 100);
$meta['accessRefusalFreq'] = array('numeric', '_min' => -1);
$meta['accessRefusalConf'] = array('numeric', '_min' => -1, '_max' => 100);
$meta['skipMgAndSp'] = array('multichoice','_choices' => array('0','sp','mg','user'));
$meta['ipWhitelist'] = array('');
$meta['emailWhitelist'] = array('');
$meta['nameWhitelist'] = array('');
$meta['userWhitelist'] = array('string');
$meta['logPlace'] = array('string');
$meta['reportAPI'] = array('string');
