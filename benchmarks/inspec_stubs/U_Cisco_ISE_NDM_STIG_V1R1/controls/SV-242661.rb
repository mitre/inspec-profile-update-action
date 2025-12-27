control 'SV-242661' do
  title 'The Cisco ISE must be configured to send log data to a central log server for the purpose of forwarding alerts to the administrators and the ISSO.'
  desc 'The aggregation of log data kept on a syslog server can be used to detect attacks and trigger an alert to the appropriate security personnel. The stored log data can used to detect weaknesses in security that enable the network IA team to find and address these weaknesses before breaches can occur. Reviewing these logs, whether before or after a security breach, are important in showing whether someone is an internal employee or an outside threat.'
  desc 'check', 'To view remote logging targets, complete the following steps:

1. From the ISE Administration Interface, choose Administration >> System >> Logging >> Remote Logging Targets.
2. The Remote Logging Targets page appears with a list of existing logging targets.

If a remote logging target is not configured, this is a finding.'
  desc 'fix', 'Create a Remote Logging Target and direct logging to that target. To create an external logging target, complete the following steps:

1. Choose Administration >> System >> Logging >> Remote Logging Targets.
2. Click "Add".
3. Configure the following fields:
- Name - Enter the name of the new target
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
3. Modify the following field values on the Log Collection page as needed.
- Name
- Target Type
- Description
- IP Address
- Port
- Facility Code
- Maximum Length
4. Click "Save".

The updating of the selected Log Collector is completed.'
  impact 0.5
  ref 'DPMS Target Cisco ISE NDM'
  tag check_id: 'C-45936r714291_chk'
  tag severity: 'medium'
  tag gid: 'V-242661'
  tag rid: 'SV-242661r714293_rule'
  tag stig_id: 'CSCO-NM-000560'
  tag gtitle: 'SRG-APP-000516-NDM-000350'
  tag fix_id: 'F-45893r714292_fix'
  tag 'documentable'
  tag cci: ['CCI-002605']
  tag nist: ['SI-2 c']
end
