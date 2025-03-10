control 'SV-242627' do
  title 'The Cisco ISE must configure a remote syslog where audit records are stored on a centralized logging target that is different from the system being audited.'
  desc 'Information stored in one location is vulnerable to accidental or incidental deletion or alteration.

Storing audit logs to a different system than that being audited is a common process in information systems with limited audit storage capacity.'
  desc 'check', 'To view remote logging targets, complete the following steps:

1. From the ISE Administration Interface, choose Administration >> System >> Logging >> Remote Logging Targets.
2. The Remote Logging Targets page appears with a list of existing logging targets.

If a remote logging target is not configured, this is a finding.'
  desc 'fix', 'Create a Remote Logging Target and direct logging to that target. To create an external logging target, complete the following steps:

1. Choose Administration >> System >> Logging >> Remote Logging Targets.
2. Click "Add".
3. Configure the following fields.
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
  tag check_id: 'C-45902r714189_chk'
  tag severity: 'medium'
  tag gid: 'V-242627'
  tag rid: 'SV-242627r714191_rule'
  tag stig_id: 'CSCO-NM-000210'
  tag gtitle: 'SRG-APP-000515-NDM-000325'
  tag fix_id: 'F-45859r714190_fix'
  tag 'documentable'
  tag cci: ['CCI-001851']
  tag nist: ['AU-4 (1)']
end
