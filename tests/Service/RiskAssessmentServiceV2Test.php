<?php

namespace OCA\RiskBasedAccountRecovery\Tests\Service;

use OCA\RiskBasedAccountRecovery\Service\RiskAssessmentServiceV2;
use OCA\RiskBasedAccountRecovery\Service\Constants;
use OCP\IDBConnection;
use OCP\DB\IPreparedStatement;
use OCP\DB\IResult;
use PHPUnit\Framework\TestCase;

class RiskAssessmentServiceV2Test extends TestCase
{
    private function mockDatabaseWithLogins(array $logins): IDBConnection {
        $mockDB = $this->createMock(IDBConnection::class);
        $mockResult = $this->createMock(IResult::class);
        $mockResult->method('fetchAll')->willReturn($logins);

        $mockStatement = $this->createMock(IPreparedStatement::class);
        $mockStatement->method('execute')->willReturn($mockResult);
        $mockStatement->method('fetchAll')->willReturn($logins);

        $mockDB->method('prepare')->willReturn($mockStatement);
        return $mockDB;
    }
    /**
     * This tests for low risk by having a past logins, and current recovery attempt not deviating from the past login values.
     */
    public function testLowRisk() {
        $pastLogins = [
            [
                'username' => 'testuser',
                'ip_address' => '192.168.1.1',
                'country' => 'Norway',
                'browser' => 'Chrome',
                'operating_system' => 'Windows',
                'login_time' => '2024-11-15 10:00:00',
            ],
            [
                'username' => 'testuser',
                'ip_address' => '192.168.1.1',
                'country' => 'Norway',
                'browser' => 'Chrome',
                'operating_system' => 'Windows',
                'login_time' => '2024-11-16 10:00:00',
            ],
            [
                'username' => 'testuser',
                'ip_address' => '192.168.1.1',
                'country' => 'Norway',
                'browser' => 'Chrome',
                'operating_system' => 'Windows',
                'login_time' => '2024-11-17 10:00:00',
            ],
            [
                'username' => 'testuser',
                'ip_address' => '192.168.1.1',
                'country' => 'Norway',
                'browser' => 'Chrome',
                'operating_system' => 'Windows',
                'login_time' => '2024-11-18 10:00:00',
            ],
            [
                'username' => 'testuser',
                'ip_address' => '192.168.1.1',
                'country' => 'Norway',
                'browser' => 'Chrome',
                'operating_system' => 'Windows',
                'login_time' => '2024-11-19 10:00:00',
            ],
            [
                'username' => 'testuser',
                'ip_address' => '192.168.1.1',
                'country' => 'Norway',
                'browser' => 'Chrome',
                'operating_system' => 'Windows',
                'login_time' => '2024-11-20 10:00:00',
            ],
            [
                'username' => 'testuser',
                'ip_address' => '192.168.1.1',
                'country' => 'Norway',
                'browser' => 'Chrome',
                'operating_system' => 'Windows',
                'login_time' => '2024-11-21 10:00:00',
            ],
            [
                'username' => 'testuser',
                'ip_address' => '192.168.1.1',
                'country' => 'Norway',
                'browser' => 'Chrome',
                'operating_system' => 'Windows',
                'login_time' => '2024-11-22 10:00:00',
            ],
            [
                'username' => 'testuser',
                'ip_address' => '192.168.1.1',
                'country' => 'Norway',
                'browser' => 'Chrome',
                'operating_system' => 'Windows',
                'login_time' => '2024-11-23 10:00:00',
            ],
            [
                'username' => 'testuser',
                'ip_address' => '192.168.1.1',
                'country' => 'Norway',
                'browser' => 'Chrome',
                'operating_system' => 'Windows',
                'login_time' => '2024-11-24 10:00:00',
            ],
        ];

        $attempt = [
            'username' => 'testuser',
            'ip_address' => '192.168.1.1',
            'country' => 'Norway',
            'browser' => 'Chrome',
            'operating_system' => 'Windows',
            'recovery_time' => '2024-04-04 10:10:00',
        ];

        $mockDB = $this->mockDatabaseWithLogins($pastLogins);
        $service = new RiskAssessmentServiceV2($mockDB);
        $result = $service->assessRisk($attempt);

        $this->assertEquals("Low Risk", $result);
    }
       
    /**
     * This tests for medium risk by having a past logins, and current recovery attempt deviating in terms of IP address and unusual hour
     */
    public function testMediumRisk() {
        $pastLogins = [
            ['username' => 'testuser', 'ip_address' => '192.168.1.1', 'country' => 'Norway', 'browser' => 'Chrome', 'operating_system' => 'Windows', 'login_time' => '2024-04-01 10:00:00'],
            ['username' => 'testuser', 'ip_address' => '192.168.1.2', 'country' => 'Norway', 'browser' => 'Firefox', 'operating_system' => 'Windows', 'login_time' => '2024-04-02 10:00:00'],
            ['username' => 'testuser', 'ip_address' => '192.168.1.1', 'country' => 'Norway', 'browser' => 'Edge', 'operating_system' => 'Windows', 'login_time' => '2024-04-03 10:00:00'],
            ['username' => 'testuser', 'ip_address' => '192.168.1.3', 'country' => 'Norway', 'browser' => 'Chrome', 'operating_system' => 'Windows', 'login_time' => '2024-04-04 10:00:00'],
            ['username' => 'testuser', 'ip_address' => '192.168.1.1', 'country' => 'Norway', 'browser' => 'Firefox', 'operating_system' => 'Windows', 'login_time' => '2024-04-05 10:00:00'],
            ['username' => 'testuser', 'ip_address' => '192.168.1.1', 'country' => 'Norway', 'browser' => 'Chrome', 'operating_system' => 'Linux', 'login_time' => '2024-04-06 10:00:00'],
            ['username' => 'testuser', 'ip_address' => '192.168.1.4', 'country' => 'Norway', 'browser' => 'Chrome', 'operating_system' => 'Windows', 'login_time' => '2024-04-07 10:00:00'],
            ['username' => 'testuser', 'ip_address' => '192.168.1.5', 'country' => 'Norway', 'browser' => 'Firefox', 'operating_system' => 'Windows', 'login_time' => '2024-04-08 10:00:00'],
            ['username' => 'testuser', 'ip_address' => '192.168.1.6', 'country' => 'Norway', 'browser' => 'Chrome', 'operating_system' => 'Windows', 'login_time' => '2024-04-09 10:00:00'],
            ['username' => 'testuser', 'ip_address' => '192.168.1.7', 'country' => 'Norway', 'browser' => 'Chrome', 'operating_system' => 'Windows', 'login_time' => '2024-04-10 10:00:00'],
        ];

        $attempt = [
            'username' => 'testuser',
            'ip_address' => '10.0.0.99', // New IP
            'country' => 'Norway',
            'browser' => 'Chrome',
            'operating_system' => 'Windows',
            'recovery_time' => '2024-04-11 23:00:00', // Unusual hour
        ];

        $mockDB = $this->mockDatabaseWithLogins($pastLogins);
        $service = new RiskAssessmentServiceV2($mockDB);
        $result = $service->assessRisk($attempt);

        $this->assertEquals("Medium Risk", $result);
    }
    /**
     * This tests for high risk by having a past logins, and current recovery attempt deviating in everything
     */     
    public function testHighRisk() {
        $pastLogins = [
            ['username' => 'testuser', 'ip_address' => '192.168.1.1', 'country' => 'Norway', 'browser' => 'Chrome', 'operating_system' => 'Windows', 'login_time' => '2024-04-01 10:00:00'],
            ['username' => 'testuser', 'ip_address' => '192.168.1.2', 'country' => 'Norway', 'browser' => 'Firefox', 'operating_system' => 'Windows', 'login_time' => '2024-04-02 10:00:00'],
            ['username' => 'testuser', 'ip_address' => '192.168.1.1', 'country' => 'Norway', 'browser' => 'Edge', 'operating_system' => 'Windows', 'login_time' => '2024-04-03 10:00:00'],
            ['username' => 'testuser', 'ip_address' => '192.168.1.3', 'country' => 'Norway', 'browser' => 'Chrome', 'operating_system' => 'Windows', 'login_time' => '2024-04-04 10:00:00'],
            ['username' => 'testuser', 'ip_address' => '192.168.1.4', 'country' => 'Norway', 'browser' => 'Chrome', 'operating_system' => 'Linux', 'login_time' => '2024-04-05 10:00:00'],
            ['username' => 'testuser', 'ip_address' => '192.168.1.5', 'country' => 'Norway', 'browser' => 'Chrome', 'operating_system' => 'Windows', 'login_time' => '2024-04-06 10:00:00'],
            ['username' => 'testuser', 'ip_address' => '192.168.1.6', 'country' => 'Norway', 'browser' => 'Firefox', 'operating_system' => 'Windows', 'login_time' => '2024-04-07 10:00:00'],
            ['username' => 'testuser', 'ip_address' => '192.168.1.7', 'country' => 'Norway', 'browser' => 'Edge', 'operating_system' => 'Windows', 'login_time' => '2024-04-08 10:00:00'],
            ['username' => 'testuser', 'ip_address' => '192.168.1.8', 'country' => 'Norway', 'browser' => 'Chrome', 'operating_system' => 'Windows', 'login_time' => '2024-04-09 10:00:00'],
            ['username' => 'testuser', 'ip_address' => '192.168.1.9', 'country' => 'Norway', 'browser' => 'Chrome', 'operating_system' => 'Windows', 'login_time' => '2024-04-10 10:00:00'],
        ];

        $attempt = [
            'username' => 'testuser',
            'ip_address' => '203.0.113.45', // Very different
            'country' => 'Brazil', // Different country
            'browser' => 'Safari',
            'operating_system' => 'macOS',
            'recovery_time' => '2024-04-04 02:00:00', // Unusual hour
        ];

        $mockDB = $this->mockDatabaseWithLogins($pastLogins);
        $service = new RiskAssessmentServiceV2($mockDB);
        $result = $service->assessRisk($attempt);

        $this->assertEquals(Constants::HIGH_RISK, $result);
    }
    /**
     * This tests for low, medium and high risks by having a stable login history data
     * It tests every low, medium and high tests 30 times and randomly changes values.
     */
    public function testRiskCategoryDistribution() {
        $mockDB = $this->createMock(IDBConnection::class);
    
        $username = 'testuser';
        $baseIp = '192.168.1.1';
        $baseCountry = 'Norway';
        $baseBrowser = 'Chrome';
        $baseOS = 'Windows 10';
        $baseTime = strtotime('2024-04-01 10:00:00');
    
        // Historical logins (stable profile)
        $logins = [];
        for ($i = 0; $i < rand(5,50); $i++) {
            $logins[] = [
                'username' => $username,
                'ip_address' => $baseIp,
                'country' => $baseCountry,
                'browser' => $baseBrowser,
                'operating_system' => $baseOS,
                'login_time' => date('Y-m-d H:i:s', $baseTime + rand(-1800, 1800)), // ±30m
            ];
        }
    
        // Mock DB setup
        $mockResult = $this->createMock(IResult::class);
        $mockResult->method('fetchAll')->willReturn($logins);
    
        $mockStatement = $this->createMock(IPreparedStatement::class);
        $mockStatement->method('execute')->willReturn($mockResult);
        $mockStatement->method('fetchAll')->willReturn($logins);
    
        $mockDB->method('prepare')->willReturn($mockStatement);
    
        $service = new RiskAssessmentServiceV2($mockDB);

        //Making a reflection object to be able to use private functions for testing
        $reflection = new \ReflectionClass(RiskAssessmentServiceV2::class);
        $method  = $reflection->getMethod('calculateContextualRisk');
        $method->setAccessible(true);
    
        $low = 0;
        $medium = 0;
        $high = 0;
        $totalPerType = 30;
        $ips = ['1.2.3.4', '5.6.7.8', '203.0.113.5']; // Example IP pool
        $browsers = ['Chrome', 'Firefox', 'Safari', 'Microsoft Edge'];
        $oses = ['Windows 10', 'Linux', 'Mac OS'];
        $foreignCountries = ['India', 'Brazil', 'Russia', 'Kenya', 'Norway'];

        $testChanges = [
            'low' => [],
            'medium' => [],
            'high' => [],
        ];
    
        // 1. Low Risk Tests (only browser changes)
        for ($i = 0; $i < $totalPerType; $i++) {

            //Generating a random browser
            $newBrowser = $browsers[array_rand($browsers)];

            $input = [
                'username' => $username,
                'ip_address' => $baseIp,
                'country' => $baseCountry,
                'browser' => $newBrowser, // only change
                'operating_system' => $baseOS,
                'recovery_time' => date('Y-m-d H:i:s', time()),
            ];
            $risk = $service->assessRisk($input);
            echo "Low Test #$i → $risk\n";
            if ($risk === Constants::LOW_RISK) $low++;
            $riskScore = $method->invoke($service,$logins,$input);
            $testChanges['low'][] = [
                'test_number' => $i+1,
                'ip_changed' => 'No',
                'country_changed' => 'No',
                'browser_changed' => ($newBrowser !==$baseBrowser) ? 'Yes' : 'No',
                'os_changed' => 'No',
                'risk_score' => $riskScore ?? '-',
                'risk_level' => $risk,
            ];


        }
    

            // 2. Medium Risk Tests (IP + OS + slight variation)
        // Medium Risk: Change 1 key context feature + slight timing shift
        for ($i = 0; $i < $totalPerType; $i++) {
            // Always change the IP
            $newIp = $ips[array_rand($ips)];
            while ($newIp === $baseIP) {
                $newIp = $ips[array_rand($ips)];
            }
        
            // Randomly decide whether to change browser or OS (but not both)
            $changeBrowser = (bool)random_int(0, 1);
            $newBrowser = $changeBrowser ? $browsers[array_rand($browsers)] : $baseBrowser;
            $newOS = !$changeBrowser ? $oses[array_rand($oses)] : $baseOS;
        
            $input = [
                'username' => $username,
                'ip_address' => $newIp,
                'country' => $baseCountry,
                'browser' => $newBrowser,
                'operating_system' => $newOS,
                'recovery_time' => date('Y-m-d H:i:s', time() + rand(-1800, 1800)), // ±30min
            ];
        
            $risk = $service->assessRisk($input);
            echo "Medium Test #$i → $risk\n";
        
            if ($risk === Constants::MEDIUM_RISK) $medium++;
            $riskScore = $method->invoke($service,$logins,$input);
            $testChanges['medium'][] = [
                'test_number' => $i+1,
                'ip_changed' => 'Yes',
                'country_changed' => 'No',
                'browser_changed' => ($newBrowser !==$baseBrowser) ? 'Yes' : 'No',
                'os_changed' => ($newOS !==$baseOS) ? 'Yes' : 'No',
                'risk_score' => $riskScore ?? '-',
                'risk_level' => $risk,
            ];
        }


    
        // 3. High Risk Tests (new country + IP + OS)
        for ($i = 0; $i < $totalPerType; $i++) {
            $newCountry = $foreignCountries[array_rand($foreignCountries)];
            $newBrowser = $browsers[array_rand($browsers)];
            $newOS = $oses[array_rand($oses)];

            $input = [
                'username' => $username,
                'ip_address' => '8.8.' . rand(0, 255) . '.' . rand(0, 255),
                'country' => $newCountry,
                'browser' => $newBrowser,
                'operating_system' => $newOS,
                'recovery_time' => date('Y-m-d H:i:s', time() + rand(36000, 43200)), // far from usual time
            ];
            $risk = $service->assessRisk($input);
            echo "High Test #$i → $risk\n";
            if ($risk === Constants::HIGH_RISK) $high++;
            $riskScore = $method->invoke($service,$logins,$input);
            $testChanges['high'][] = [
                'test_number' => $i+1,
                'ip_changed' => 'Yes',
                'country_changed' => ($newCountry!==$baseCountry) ? 'Yes' : 'No',
                'browser_changed' => ($newBrowser !==$baseBrowser) ? 'Yes' : 'No',
                'os_changed' => ($newOS !==$baseOS) ? 'Yes' : 'No',
                'risk_score' => $riskScore ?? '-',
                'risk_level' => $risk,
            ];
        }

        $totalPastLogins = count($logins);
        // Summary

        
        foreach (['low', 'medium', 'high'] as $riskTest) {
            echo "\n----- $riskTest -----\n";
            foreach ($testChanges[$riskTest] as $i => $change) {
                echo "Test #". ($change['test_number']) . "\n";
                echo "IP changed: ". ($change['ip_changed']) . "\n";
                echo "Country changed: ". ($change['country_changed']) . "\n";
                echo "Browser changed: ". ($change['browser_changed']) . "\n";
                echo "OS changed: ". ($change['os_changed']) . "\n";
                echo "Risk Score: ". ($change['risk_score']) . "\n";
                echo "Risk Level: ". ($change['risk_level']) . "\n";
                echo "\n----------\n";
            }
        }

        echo "Amount of past logins: $totalPastLogins\n";
        echo "Low Risk Detected: $low / $totalPerType\n";
        echo "Medium Risk Detected: $medium / $totalPerType\n";
        echo "High Risk Detected: $high / $totalPerType\n";
        
        // Optional assertions
        $this->assertGreaterThan(15, $low, "Too few Low Risk detections.");
        $this->assertGreaterThan(10, $medium, "Too few Medium Risk detections.");
        $this->assertGreaterThan(20, $high, "Too few High Risk detections.");
    }
        
        
        
        
    
    
    
}
