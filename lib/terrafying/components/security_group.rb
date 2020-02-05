require 'terrafying/components/usable'
require 'terrafying'

module Terrafying
    module Components
       class SecurityGroup < Terrafying::Context
        include Usable
        def self.create_in(vpc, name, ports:)
            new.create_in(vpc, name, ports: ports)
        end
        
        def create_in(vpc, name, ports:)
            @name = name
            @ports = ports
            @security_group_ref = resource :aws_security_group, tf_safe(name),{

                vpc_id: vpc.id,
                name: name,
                tags: {
                    'Name' => name
                  }
            }
            @security_group = @security_group_ref[:id]
            self
        end
        
       end         

    end
end