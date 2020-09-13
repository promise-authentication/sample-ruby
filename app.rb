require 'sinatra'
require 'sinatra/cookies'
require "sinatra/reloader" if development?

require 'json/jwt'
require 'net/https'
require 'httparty'

class NonceNotMatching < StandardError ; end

get '/' do
  render_go_on
end

def render_go_on(error = nil)
  cookies[:nonce] = SecureRandom.uuid

  erb :go_on, locals: {
    error: error,
    href: "https://promiseauthentication.org/a/ruby.promiseauthentication.org?nonce=#{ cookies[:nonce] }" 
  }
end

get '/authenticate' do
  error = nil

  begin
    string = params[:id_token]
    payload = JSON::JWT.decode(string , :skip_verification)
    jwks_url = "#{payload['iss']}/.well-known/jwks.json"
    jwks = JSON.parse(HTTParty.get(jwks_url).body)

    decoded_token = nil
    jwks["keys"].each do |jwk|
      break if decoded_token
      key = JSON::JWK.new(jwk).to_key
      begin
        decoded_token = JSON::JWT.decode string, key
      rescue => e
        error = e
      end
    end

    user_id = [payload['iss'], payload['sub']].join('|')

    nonce = payload['nonce']
    error ||= NonceNotMatching.new("Nonce in id_token is not matching the nonce from the authentication request.") if nonce != cookies[:nonce]

    erb :index, locals: {
      payload: payload,
      nonce: nonce,
      header: payload.header,
      jwks_url: jwks_url,
      jwks: jwks,
      decoded_token: decoded_token,
      user_id: user_id,
      error: error
    }
  rescue => e
    render_go_on(e)
  end
end

get '/.well-known/promise.json' do
  etag ENV['HEROKU_SLUG_COMMIT'] || SecureRandom.uuid
  cache_control :public, :must_revalidate, :max_age => 60*5 # 5 minutes
  content_type 'application/json'
  {
    name: 'Sandbox',
    logo_url: 'https://upload.wikimedia.org/wikipedia/commons/d/d5/Minimalist_Sandbox_Icon.png',
    locale: 'en',
    admin_user_ids: [
      "c8189582-e3c1-4fcf-97a6-ee9649d10c61", # Anders localhost
      "82802bca-7290-4b76-ae27-4a75ed14b3c4" # Anders production
    ]
  }.to_json
end
