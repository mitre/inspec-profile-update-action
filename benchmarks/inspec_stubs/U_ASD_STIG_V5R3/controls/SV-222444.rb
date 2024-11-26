control 'SV-222444' do
  title 'The application must not write sensitive data into the application logs.'
  desc 'It is important to identify and exclude certain types of data that is written into the logs. If the logs are compromised and sensitive data is included in the logs, this could assist an attacker in furthering their attack or it could completely compromise the system.

Examples of such data include but are not limited to; Passwords, Session IDs, Application source code, encryption keys, and sensitive data such as personal health information (PHI), Personally Identifiable Information (PII), or government identifiers (e.g., SSN).'
  desc 'check', 'Review the application logs and identify application logging format. Using the format of the log and the requisite search data as a guide to create your search, create search strings that could successfully identify the existence of passwords, session IDs, or other sensitive information such as SSN.

Utilizing the UNIX grep-based search utility include the following examples which are meant to illustrate the purpose of the requirement.

Password values are usually associated with usernames so searching for "username" in the provided log file will often assist in determining if password values are included.

grep -i "username" <  logfile.txt

Search for social security numbers in the provided log file.

grep -i "[0-9]{3}[-]?[0-9]{2}[-]?[0-9]{4}" <  logfile.txt

Use regular expressions to aid in searching log files. All search syntax cannot be provided within the STIG, the reviewer must utilize their knowledge to create new search criteria based upon the log format used and the potentially sensitive data processed by the application.

If the application logs sensitive data such as session IDs, application source code, encryption keys, or passwords, this is a finding.'
  desc 'fix', 'Design or reconfigure the application to not write sensitive data to the logs.'
  impact 0.5
  ref 'DPMS Target Application Security and Development'
  tag check_id: 'C-24114r493240_chk'
  tag severity: 'medium'
  tag gid: 'V-222444'
  tag rid: 'SV-222444r879559_rule'
  tag stig_id: 'APSC-DV-000650'
  tag gtitle: 'SRG-APP-000089'
  tag fix_id: 'F-24103r493241_fix'
  tag 'documentable'
  tag legacy: ['SV-83991', 'V-69369']
  tag cci: ['CCI-000169']
  tag nist: ['AU-12 a']
end
