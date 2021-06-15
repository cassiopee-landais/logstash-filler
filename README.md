# logstash-filter
filter {
 grok {
      match => { "message" => "%{COMBINEDAPACHELOG}" }
    }
 mutate {
        convert => {
            "response" => "integer"
            "bytes" => "integer"
        }
}
  fingerprint {
    source => "message"
    target => "[@metadata][fingerprint]"
    method => "MURMUR3"
  }

 if [clientip] {
        memcached {
                hosts => ["memcached:11211"]
                namespace => "misp-ip"
                get => {"%{[clientip]}" => "[enrich][tmp]" }
        }
        if [enrich][tmp] {
            ruby { path => "/etc/logstash/process_ioc.rb" }
            mutate { remove_field => [ "[enrich]" ] }
         }

        if ![enrich][tmp]{
                mutate { remove_field => [ "[enrich][tmp]" ]
    }

 }
}
}
