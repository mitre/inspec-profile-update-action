control 'SV-204579' do
  title 'The Red Hat Enterprise Linux operating system must be configured so that all network connections associated with a communication session are terminated at the end of the session or after 15 minutes of inactivity from the user at a command prompt, except to fulfill documented and validated mission requirements.'
  desc 'Terminating an idle session within a short time period reduces the window of opportunity for unauthorized personnel to take control of a management session enabled on the console or console port that has been left unattended. In addition, quickly terminating an idle session will also free up resources committed by the managed network element. 

Terminating network connections associated with communications sessions includes, for example, de-allocating associated TCP/IP address/port pairs at the operating system level and de-allocating networking assignments at the application level if multiple application sessions are using a single operating system-level network connection. This does not mean that the operating system terminates all sessions or network access; it only ends the inactive session and releases the resources associated with that session.

'
  desc 'check', 'Verify the operating system terminates all network connections associated with a communications session at the end of the session or based on inactivity.

Check the value of the system inactivity timeout with the following command:

$ sudo grep -irw tmout /etc/profile /etc/bashrc /etc/profile.d

etc/profile.d/tmout.sh:declare -xr TMOUT=900

If conflicting results are returned, this is a finding.
If "TMOUT" is not set to "900" or less to enforce session termination after inactivity, this is a finding.'
  desc 'fix', 'Configure the operating system to terminate all network connections associated with a communications session at the end of the session or after a period of inactivity.

Create a script to enforce the inactivity timeout (for example /etc/profile.d/tmout.sh) such as:

#!/bin/bash

declare -xr TMOUT=900'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 7'
  tag check_id: 'C-4703r858485_chk'
  tag severity: 'medium'
  tag gid: 'V-204579'
  tag rid: 'SV-204579r861070_rule'
  tag stig_id: 'RHEL-07-040160'
  tag gtitle: 'SRG-OS-000163-GPOS-00072'
  tag fix_id: 'F-4703r646843_fix'
  tag satisfies: ['SRG-OS-000029-GPOS-00010', 'SRG-OS-000163-GPOS-00072']
  tag 'documentable'
  tag legacy: ['SV-86847', 'V-72223']
  tag cci: ['CCI-001133', 'CCI-002361']
  tag nist: ['SC-10', 'AC-12']
end
