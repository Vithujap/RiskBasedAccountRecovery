# RiskBasedAccountRecovery

This is a Risk-Based Account Recovery system, an app for the Nextcloud platform. It enhances the security of the account recovery process by performing a risk assessment using contextual attributes from past logins and comparing them to the recovery attempt. This is part of a master's thesis to display a functional proof of concept for a Risk-Based Account Recovery system. 

## Getting Started
To run this app on your own Nextcloud enviornment, do the following:
1. **Clone the repository** into the Nextcloud apps directory: `git clone https://github.com/Vithujap/RiskBasedAccountRecovery.git`
2. Ensure the app has the correct permissions: `chown -R www-data:www-data /path/to/nextcloud/apps/RiskBasedAccountRecovery`
3. Enable the app through the Nextcloud Web UI under apps, or through the command line using the following command: `sudo -u www-data php /path/to/nextcloud/occ app:enable RiskBasedAccountRecovery`

## Running Unit Tests
This project utilized Unit Testing to simulate recovery attempts with simulated data.
### Prerequisites
Make sure you have the following installed:
- [PHP](https://www.php.net/manual/en/install.php)
- [Composer](https://getcomposer.org/download/)
### Setup Instructions
1. Go to the root of the RiskBasedAccountRecovery directory.
2. Run the command: `composer install`
### Run the tests:
Run the following command in the root of the RiskBasedAccountRecovery directory: `./vendor/bin/phpunit --verbose --bootstrap tests/bootstrap.php tests`

