control 'SV-257526' do
  title 'The Red Hat Enterprise Linux CoreOS (RHCOS) chrony Daemon must use multiple NTP servers to generate audit record time stamps.'
  desc 'Utilizing multiple NTP servers for the chrony daemon in RHCOS ensures accurate and reliable audit record timestamps. It improves time synchronization, mitigates time drift, provides redundancy, and enhances resilience against attacks. Knowing when a sequence of events for an incident occurred is crucial to understand what may have taken place. Without a common clock, the components generating audit events could be out of synchronization and would then present a picture of the event that is warped and corrupted. To give a clear picture, it is important that the container platform and its components use a common internal clock.'
  desc 'check', %q(Verify Red Hat Enterprise Linux CoreOS (RHCOS) chrony Daemon is configured to use multiple NTP servers by executing the following:

for node in $(oc get node -oname); do oc debug $node -- chroot /host /bin/bash -c 'echo -n "$HOSTNAME "; grep "server" /etc/chrony.d/*' 2>/dev/null; done

(Sample output: server <SERVER1.EXAMPLE.COM> minpoll 4 maxpoll 10
server <SERVER2.EXAMPLE.COM> minpoll 4 maxpoll 10)

If multiple NTP servers are not configured, this is a finding.)
  desc 'fix', 'Apply the machine config by executing the following, replacing the variables in the MachineConfig with organizationally-defined NTP servers.

for mcpool in $(oc get mcp -oname | sed ""s:.*/::"" ); do
echo "apiVersion: machineconfiguration.openshift.io/v1
kind: MachineConfig
metadata:
  name: 90-chrony-ntp-servers-set-$mcpool
  labels:
    machineconfiguration.openshift.io/role: $mcpool
spec:
  config:
    ignition:
      version: 3.1.0
      storage:
        files:
        - contents:
            source: data:,%23%20Allow%20for%20extra%20configuration%20files.%20This%20is%20useful%0A%23%20for%20admins%20specifying%20their%20own%20NTP%20servers%0Ainclude%20%2Fetc%2Fchrony.d%2F%2A.conf%0A%0A%23%20Set%20chronyd%20as%20client-only.%0Aport%200%0A%0A%23%20Disable%20chronyc%20from%20the%20network%0Acmdport%200%0A%0A%23%20Record%20the%20rate%20at%20which%20the%20system%20clock%20gains%2Flosses%20time.%0Adriftfile%20%2Fvar%2Flib%2Fchrony%2Fdrift%0A%0A%23%20Allow%20the%20system%20clock%20to%20be%20stepped%20in%20the%20first%20three%20updates%0A%23%20if%20its%20offset%20is%20larger%20than%201%20second.%0Amakestep%201.0%203%0A%0A%23%20Enable%20kernel%20synchronization%20of%20the%20real-time%20clock%20%28RTC%29.%0Artcsync%0A%0A%23%20Enable%20hardware%20timestamping%20on%20all%20interfaces%20that%20support%20it.%0A%23hwtimestamp%20%2A%0A%0A%23%20Increase%20the%20minimum%20number%20of%20selectable%20sources%20required%20to%20adjust%0A%23%20the%20system%20clock.%0A%23minsources%202%0A%0A%23%20Allow%20NTP%20client%20access%20from%20local%20network.%0A%23allow%20192.168.0.0%2F16%0A%0A%23%20Serve%20time%20even%20if%20not%20synchronized%20to%20a%20time%20source.%0A%23local%20stratum%2010%0A%0A%23%20Require%20authentication%20%28nts%20or%20key%20option%29%20for%20all%20NTP%20sources.%0A%23authselectmode%20require%0A%0A%23%20Specify%20file%20containing%20keys%20for%20NTP%20authentication.%0Akeyfile%20%2Fetc%2Fchrony.keys%0A%0A%23%20Insert%2Fdelete%20leap%20seconds%20by%20slewing%20instead%20of%20stepping.%0A%23leapsecmode%20slew%0A%0A%23%20Get%20TAI-UTC%20offset%20and%20leap%20seconds%20from%20the%20system%20tz%20database.%0Aleapsectz%20right%2FUTC%0A%0A%23%20Specify%20directory%20for%20log%20files.%0Alogdir%20%2Fvar%2Flog%2Fchrony%0A%0A%23%20Select%20which%20information%20is%20logged.%0A%23log%20measurements%20statistics%20tracking
            mode: 420
            overwrite: true
            path: /etc/chrony.conf
        - contents:
            source: data:,
          mode: 420
          overwrite: true
          path: /etc/chrony.d/.mco-keep
        - contents:
             source: data:,%23%0A%23%20This%20file%20controls%20the%20configuration%20of%20the%20ntp%20server%0A%23%200.pool.ntp.org%2C1.pool.ntp.org%2C2.pool.ntp.org%2C3.pool.ntp.org%20we%20have%20to%20put%20variable%20array%20name%20here%20for%20mutilines%20remediation%20%0A%0Aserver%20<SERVER1.EXAMPLE.COM>%20minpoll%204%20maxpoll%2010%0Aserver%20<SERVER2.EXAMPLE.COM>%20minpoll%204%20maxpoll%2010%0Aserver%20<SERVER3.EXAMPLE.COM>%20minpoll%204%20maxpoll%2010%0Aserver%20<SERVER4.EXAMPLE.COM>%20minpoll%204%20maxpoll%2010%0A
          mode: 420
          overwrite: true
          path: /etc/chrony.d/ntp-server.conf
" | oc apply -f -
done'
  impact 0.5
  ref 'DPMS Target Red Hat OpenShift Container Platform 4.12'
  tag check_id: 'C-61261r921519_chk'
  tag severity: 'medium'
  tag gid: 'V-257526'
  tag rid: 'SV-257526r921521_rule'
  tag stig_id: 'CNTR-OS-000240'
  tag gtitle: 'SRG-APP-000116-CTR-000235'
  tag fix_id: 'F-61185r921520_fix'
  tag 'documentable'
  tag cci: ['CCI-000159']
  tag nist: ['AU-8 a']
end
