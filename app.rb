require 'sinatra'
require "sinatra/reloader" if development?

require 'json'
require 'jwt'
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
    payload, header = JWT.decode(string , nil, false)
    jwks_url = "https://#{payload['iss']}/.well-known/jwks.json"
    jwks = JSON.parse(HTTParty.get(jwks_url).body)

    jwk = jwks["keys"].first
    key = JSON::JWK.new(jwk).to_key
    begin
      decoded_token = JWT.decode string, key, true, { algorithm: header['alg'] }
    rescue => e
      error = e
    end

    user_id = [payload['iss'], payload['sub']].join('|')

    erb :index, locals: {
      payload: payload,
      header: header,
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
  expires 60*5 # minutes
  content_type 'application/json'
  {
    name: 'Ruby App',
    logo_url: 'https://pngimg.com/uploads/ruby/ruby_PNG47.png',
    locale: 'en'
  }.to_json
end
