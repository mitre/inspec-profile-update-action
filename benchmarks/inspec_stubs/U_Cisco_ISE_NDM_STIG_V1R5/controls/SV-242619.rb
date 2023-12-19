control 'SV-242619' do
  title 'The Cisco ISE must protect against an individual (or process acting on behalf of an individual) falsely denying having performed organization-defined actions to be covered by non-repudiation.'
  desc 'This requirement supports non-repudiation of actions taken by an administrator and is required in order to maintain the integrity of the configuration management process. All configuration changes to the network device are logged, and administrators authenticate with two-factor authentication before gaining administrative access. Together, these processes will ensure the administrators can be held accountable for the configuration changes they implement.

To meet this requirement, the network device must log administrator access and activity.'
  desc 'check', 'To view remote logging targets, complete the following steps:

1. From the ISE Administration Interface, choose Administration >> System >> Logging >> Remote Logging Targets.
2. The Remote Logging Targets page appears with a list of existing logging targets.

If a remote logging target is not configured, this is a finding.'
  desc 'fix', %q(Create a secure syslog remote logging target and direct logging to that site's central syslog or events server. To create an external logging target, complete the following steps:

1. Choose Administration >> System >> Logging >> Remote Logging Targets.
2. Click "Add".
3. Configure the following fields:
- Name - Enter the name of the new target.
- Target Type - By default it is set to Syslog. The value of this field cannot be changed.
- Description - Enter a brief description of the new target.
- IP Address - Enter the IP address of the destination machine where you want to store the logs.
- Port - Enter the port number of the destination machine.
- Facility Code - Choose the syslog facility code to be used for logging. Valid options are Local0 through Local7.
- Maximum Length - Enter the maximum length of the remote log target messages. Valid options are from 200 to 1024 bytes.
4. Click "Save".

Go to the Logging Targets page and verify the creation of the new target. To edit a remote logging target, complete the following steps:

1. Choose Administration >> System >> Logging >> Remote Logging Targets.
2. Click the radio button next to the logging target name that you want to edit and click "Edit".
3. Modify the following field values on the Log Collection page as needed:
- Name
- Target Type
- Description
- IP Address
- Port
- Facility Code
- Maximum Length
4. Click "Save".

The updating of the selected Log Collector is completed.)
  impact 0.5
  ref 'DPMS Target Cisco ISE NDM'
  tag check_id: 'C-45894r714165_chk'
  tag severity: 'medium'
  tag gid: 'V-242619'
  tag rid: 'SV-242619r879554_rule'
  tag stig_id: 'CSCO-NM-000130'
  tag gtitle: 'SRG-APP-000080-NDM-000220'
  tag fix_id: 'F-45851r714166_fix'
  tag 'documentable'
  tag cci: ['CCI-000166']
  tag nist: ['AU-10']
end
