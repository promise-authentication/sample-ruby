require 'sinatra'
require "sinatra/reloader" if development?

require 'json/jwt'
require 'net/https'
require 'httparty'

get '/' do
  erb :go_on, locals: { error: nil }
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

    erb :index, locals: {
      payload: payload,
      header: payload.header,
      jwks_url: jwks_url,
      jwks: jwks,
      decoded_token: decoded_token,
      user_id: user_id,
      error: error
    }
  rescue => e
    error = e
    erb :go_on, locals: { error: error }
  end
end

get '/.well-known/promise.json' do
  etag ENV['HEROKU_SLUG_COMMIT'] || SecureRandom.uuid
  cache_control :public, :must_revalidate, :max_age => 60*5 # 5 minutes
  content_type 'application/json'
  {
    name: 'Sample Ruby App',
    logo_url: 'https://pngimg.com/uploads/ruby/ruby_PNG47.png',
    locale: 'en',
    admin_user_ids: [
      "c8189582-e3c1-4fcf-97a6-ee9649d10c61", # Anders localhost
      "82802bca-7290-4b76-ae27-4a75ed14b3c4" # Anders production
    ]
  }.to_json
end
