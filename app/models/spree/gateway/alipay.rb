module Spree
  class Gateway::Alipay < Gateway
    preference :pid, :string
    preference :email, :string
    preference :key, :string
    preference :iconUrl, :string
    preference :returnHost, :string
    preference :server_public_key, :string
    preference :client_private_key, :string

    def supports?(source)
      true
    end

    def provider
    end

    def purchase(amount, express_checkout, gateway_options={})
      Class.new do
        def success?; true; end
        def authorization; nil; end
      end.new
    end

    def auto_capture?
      true
    end

    def method_type
      'alipay'
    end

  end
end
