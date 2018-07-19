#!/usr/bin/env ruby


require 'openssl'
require 'base64'

if ARGV.length < 1
  puts 'you need to specify the file to open'
  exit
end

input_file = File.open(ARGV[0],'r+').readlines
output_file = File.new('kubernetes_certs.csv' , 'a+')
dns_output_file = File.new('dns_names.csv','a+')
ip_address_file = File.new('ip_addresses.csv','a+')
cn_file = File.new('cns.csv','a+')
stats_file = File.new('stats.txt','a+')


@dns_names = Hash.new
@ip_addresses = Hash.new
@cns = Array.new


input_file.each do |line|
  encoded_cert = line.split(',')[1].chomp
  decoded_cert = Base64.decode64(encoded_cert)
  cert = OpenSSL::X509::Certificate.new(decoded_cert)
  cert_cn = cert.subject.to_s
  
  san = cert.extensions.find {|e| e.oid == "subjectAltName"}

  begin
  	if san.value.downcase =~ /kubernetes/
      @cns << cert_cn.split('=')[1]
	  	#puts 'got a Kubernetes cert, CN : ' + cert_cn + ' Subject Alt Names ' + san.value
	  	output_file.puts cert_cn + ',' + san.value
      sans = san.value.split(', ')
      sans.each do |san|
        if san =~ /^IP/
          ip = san.split(':')[1]
          if @ip_addresses[ip]
            @ip_addresses[ip] = @ip_addresses[ip] + 1
          else
            @ip_addresses[ip] = 1
          end
        elsif san =~ /DNS/
          dns = san.split(':')[1]
          if @dns_names[dns]
            @dns_names[dns] = @dns_names[dns] + 1
          else
            @dns_names[dns] = 1
          end
        end
      end
  	end
  rescue NoMethodError
  	#we know what this is
  end
end

@dns_names.each {|name, amount| dns_output_file.puts name + ',' + amount.to_s}
@ip_addresses.each {|ip, amount| ip_address_file.puts ip + ',' + amount.to_s}
@cns.each {|cn| cn_file.puts cn}