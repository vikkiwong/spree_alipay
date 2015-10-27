module Spree
  class AlipayController < StoreController
    skip_before_filter :verify_authenticity_token
    skip_before_filter :check_domain

    def alipay_timestamp
      Timeout::timeout(10){ HTTParty.get(alipay_url('service' => 'query_timestamp')) }['alipay']['response']['timestamp']['encrypt_key']
    end

    def alipay_url(options)
      options.merge!({
        'seller_email' => payment_method.preferences[:email],
        'partner' => payment_method.preferences[:pid],
        '_input_charset' => 'utf-8',
      })
      options.merge!({
        'sign_type' => 'MD5',
        'sign' => Digest::MD5.hexdigest(options.sort.map{|k,v|"#{k}=#{v}"}.join("&")+payment_method.preferences[:key]),
      })
      action = "https://mapi.alipay.com/gateway.do"
      cgi_escape_action_and_options(action, options)
    end

    def alipay_wallet_url(options)
      options.merge!({
        'service' => 'mobile.securitypay.pay',
        'seller_id' => payment_method.preferences[:email],
        'partner' =>payment_method.preferences[:pid],
        '_input_charset' => 'utf-8',

      })

      key = OpenSSL::PKey::RSA.new(payment_method.preferences[:client_private_key].gsub('\n', "\n"))

      options.merge!({
        'sign_type' => 'RSA',
        'sign' => CGI::escape(Base64.encode64(key.sign(OpenSSL::Digest::SHA1.new, options.map{|k,v| "#{k}=\"#{v}\"" }.join('&'))).gsub("\n", '')),
      })
      options.map{|k,v| "#{k}=\"#{v}\"" }.join('&')
    end

    def cgi_escape_action_and_options(action, options) # :nodoc: all
      "#{action}?#{options.sort.map{|k, v| "#{CGI::escape(k.to_s)}=#{CGI::escape(v.to_s)}" }.join('&')}"
    end

    def pay_options(order, bank = nil)
      return_host = payment_method.preferences[:returnHost].blank? ? request.url.sub(request.fullpath, '') : payment_method.preferences[:returnHost]
      show_url = params[:redirect_url].blank? ? (request.url.sub(request.fullpath, '') + '/products/' + order.products[0].slug) : params[:redirect_url]

      options = {
          'subject' => "#{order.line_items[0].product.name.slice(0,30)}等#{order.line_items.count}件",
          'body' => "#{order.number}",
          'out_trade_no' => order.number,
          'service' => 'create_direct_pay_by_user',
          'total_fee' => order.total,
          'show_url' => show_url,
          'return_url' => return_host + '/alipay/notify?id=' + order.id.to_s + '&payment_method_id=' + params[:payment_method_id].to_s,
          'notify_url' => return_host + '/alipay/notify?source=notify&id=' + order.id.to_s + '&payment_method_id=' + params[:payment_method_id].to_s,
          'payment_type' => '1',
          'anti_phishing_key' => alipay_timestamp,
          'sign_id_ext' => order.user.blank? ? 'no_user_id' : order.user.id,
          'sign_name_ext' => order.email.blank? ? (order.phone.blank? ? 'no_user_detail' : order.phone ) : order.email,
          'exter_invoke_ip' => request.remote_ip
      }
      # 钱包支付
      return alipay_wallet_url(options.slice('subject', 'body', 'out_trade_no', 'total_fee', 'notify_url', 'payment_type')) if bank == 'wallet'

      # 网页支付
      url = alipay_url(options)
    end

    def checkout
      order = current_order || raise(ActiveRecord::RecordNotFound)
      respond_to do |format|
        format.html { redirect_to self.pay_options(order,nil) }
        format.json  { render json: {'url' => self.pay_options(order,nil)} }
      end
    end

    def checkout_api
      # order = Spree::Order.find(params[:id])  || raise(ActiveRecord::RecordNotFound)
      order_set = OrderSet.new(params[:id])

      # 钱包支付
      render json:  { 'url' => self.pay_options(order_set, 'wallet') }
    end

    def notify
      # order = Spree::Order.find(params[:id]) || raise(ActiveRecord::RecordNotFound)
      order_set = OrderSet.new(params[:id])
      if order_set.orders.all? { |order| order.complete? }
        success_return order_set
        return
      end

      # if order.complete?
      #   success_return order
      #   return
      # end

      request_valid = Timeout::timeout(10){ HTTParty.get("https://mapi.alipay.com/gateway.do?service=notify_verify&partner=#{payment_method.preferences[:pid]}&notify_id=#{params[:notify_id]}") }

      unless request_valid && params[:total_fee] == order_set.total.to_s
        failure_return order_set
        return
      end

      # unless params['sign'].downcase == Digest::MD5.hexdigest(params.except(*%w[id sign_type sign source payment_method_id]).sort.map{|k,v| "#{k}=#{CGI.unescape(v.to_s)}" }.join("&")+ payment_method.preferences[:key])
      #   failure_return order
      #   return
      # end

      order_set.orders.each do |order|
        order.payments.create!({
          :source => Spree::AlipayNotify.create({
            :out_trade_no => params[:out_trade_no],
            :trade_no => params[:trade_no],
            :seller_email => params[:seller_email],
            :buyer_email => params[:buyer_email],
            :total_fee => params[:total_fee],
            :source_data => params.to_json
          }),
          :amount => order.total,
          :payment_method => payment_method
      })

      order.next
      end


      if order_set.orders.all? { |order| order.complete? }
        success_return order_set
      else
        failure_return order_set
      end
    end

    def query
      order = Spree::Order.find(params[:id]) || raise(ActiveRecord::RecordNotFound)

      if order.complete?
        render json: { 'errCode' => 0, 'msg' => 'success'}
        return
      end

      r = begin
        Timeout::timeout(10) do
          r = HTTParty.get(alipay_url('out_trade_no' => order.number, 'service' => 'single_trade_query'))
          Rails.logger.info "alipay_query #{r.inspect}"
          r
        end
      rescue Exception => e
        Rails.logger.info "alipay_query_exception #{r.inspect}"
        false
      end

      if r && r['alipay'] && r['alipay']['response'] && r['alipay']['response']['trade'] && %w[TRADE_FINISHED TRADE_SUCCESS].include?(r['alipay']['response']['trade']['trade_status']) && r['alipay']['is_success'] == 'T' && r['alipay']['sign'] == Digest::MD5.hexdigest(r['alipay']['response']['trade'].sort.map{|k,v|"#{k}=#{v}"}.join("&") + payment_method.preferences[:key])
        order.payments.create!({
          :source => Spree::AlipayNotify.create({
            :out_trade_no => r['alipay']['response']['trade']['out_trade_no'],
            :trade_no => r['alipay']['response']['trade']['trade_no'],
            :seller_email => r['alipay']['response']['trade']['seller_email'],
            :buyer_email => r['alipay']['response']['trade']['buyer_email'],
            :total_fee => r['alipay']['response']['trade']['total_fee'],
            :source_data => r['alipay']['response']['trade'].to_json
          }),
          :amount => order.total,
          :payment_method => payment_method
        })
        order.next
        if order.complete?
          render json: { 'errCode' => 0, 'msg' => 'success'}
        else
          render json: { 'errCode' => 1, 'msg' => 'failure'}
        end
      else
        render json: { 'errCode' => 1, 'msg' => 'failure'}
      end
    end

    def success_return(order)
      if params[:source] == 'notify'
        render :text => "success", :layout => false
      else
        redirect_to "/orders/#{order.number}"
      end
    end

    def failure_return(order)
      if params[:source] == 'notify'
        render :text => "failure", :layout => false
      else
        redirect_to "/orders/#{order.number}"
      end
    end

    def payment_method
      Spree::PaymentMethod.find(params[:payment_method_id])
    end

    class OrderSet
      attr_reader :orders
      def initialize(pid)
        @orders = Spree::Order.where(id: pid.to_s.split(",").map(&:to_i)).to_a
        raise ActiveRecord::RecordNotFound if @orders.blank?
      end

      def id
        orders.map(&:id).join(',')
      end

      def number
        orders.map(&:number).join('')
      end

      def total
        orders.sum(&:total)
      end

      def line_items
        orders.map(&:line_items).flatten
      end

      def products
        orders.map(&:products).flatten
      end

      def user
        orders[0].user
      end

      def email
        orders[0].email
      end

      def phone
        orders[0].phone
      end


    end

  end
end