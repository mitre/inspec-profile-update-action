control 'SV-242592' do
  title 'The Cisco ISE must be configured to log records onto a centralized events server. This is This is required for compliance with C2C Step 1.'
  desc 'Without the ability to centrally manage the content captured in the log records, identification, troubleshooting, and correlation of suspicious behavior would be difficult and could lead to a delayed or incomplete analysis of an ongoing attack.

The DoD requires centralized management of all network component audit record content. Since audit failure detection is required, a connection-oriented protocol must be configured for communication with the centralized events server.

This requirement does not apply to audit logs generated on behalf of the device itself (management).'
  desc 'check', 'If DoD is not at C2C Step 1 or higher, this is not a finding.
To view remote logging targets, complete the following steps:

1. From the ISE Administration Interface, choose Administration >> System >> Logging >> Remote Logging Targets.
2. The Remote Logging Targets page appears with a list of existing logging targets.

If a remote logging target is not configured, this is a finding.'
  desc 'fix', 'Create a Remote Logging Target and direct logging to that target. To create an external logging target, complete the following steps.

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
  ref 'DPMS Target Cisco ISE NAC'
  tag check_id: 'C-45867r812765_chk'
  tag severity: 'medium'
  tag gid: 'V-242592'
  tag rid: 'SV-242592r855853_rule'
  tag stig_id: 'CSCO-NC-000180'
  tag gtitle: 'SRG-NET-000333-NAC-001340'
  tag fix_id: 'F-45824r714085_fix'
  tag 'documentable'
  tag cci: ['CCI-001844']
  tag nist: ['AU-3 (2)']
end
