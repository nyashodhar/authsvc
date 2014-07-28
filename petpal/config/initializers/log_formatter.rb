class ActiveSupport::Logger::SimpleFormatter
  SEVERITY_TO_TAG_MAP     = {'DEBUG'=>'DEBUG', 'INFO'=>'INFO', 'WARN'=>'WARN', 'ERROR'=>'ERROR', 'FATAL'=>'PANTSONFIRE', 'UNKNOWN'=>'UNKNOWN'}
  USE_HUMOROUS_SEVERITIES = true
 
  def call(severity, time, progname, msg)
    formatted_severity = sprintf("%-3s",SEVERITY_TO_TAG_MAP[severity])
 
    formatted_time = time.strftime("%Y-%m-%d %H:%M:%S.") << time.usec.to_s[0..2].rjust(3)
    
    "\033[m#{formatted_time}\033[0m [\033[#{}m#{formatted_severity}\033[0m] #{msg.strip} (pid:#{$$})\n"
  end
end