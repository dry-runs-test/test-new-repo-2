// This special test file is an integration test for production hyperscan providers
// Its runs an identical set of checks on all our configured hyperscan providers
package hypercredscan

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/flier/gohs/hyperscan"
	"github.com/github/go-stats"
	"github.com/stretchr/testify/require"

	"github.com/github/token-scanning-service/hypercredscan/hypercredscan/config"
	"github.com/github/token-scanning-service/hypercredscan/hypercredscan/processors"
)

var (
	prodConfig    *config.Config
	exampleTokens = map[string][]exampleToken{
		"ADAFRUIT_AIO_KEY": {
			{input: "aio_FMBo07xPM4e0Aj3eYjO23blItBvS"},
			{input: "aio_AFAl78NPVow9ATNDZ0AgvICgLygp"},
			{input: "aio_HKhn497s5qA21gC1iwSn4V5qTjV0"},
			{input: "aio_XoSD69IcBnZXuIaRrpgQPgx5yBWw"},
			{input: "aio_CRBx05fcMyPGexgVVUauFgABOqll"},
		},
		"AIRTABLE_API_KEY": {
			// Generated from https://airtable.com/account.
			{input: "key1RFqWNTMTxYyoC"},
			{input: "keyVCF6kSv0JhLDFH"},
		},
		"AIRTABLE_NAME_PRESENCE": {
			{input: "airtable"},
			{input: "AIRTABLE"},
			{input: "AirtableCredentials", matches: []string{"Airtable"}},
		},
		"AIVEN_AUTH_TOKEN": {
			{input: "AVNU_aFZiqrGgdNgpssbvmZdevdw66oW4sLKzbTydKX93rfmJXLQPWXiR/XytzYa8DQQWSYUnfeROpFqaLd8QrKbh+Pt/v8UN3APnxBzN1jiLyoINyHi64ZFzvcjmqeH1bOPR5hDEZC3K7YGZBpFmiqa+YjnKevuoIvLTCiDa9TmHe5VUmAwi49c6AfeCsZSn+yK7A90OgOB0gK2JU/nfvyAS1gWxkNunPgg5zEJvR67PAmUlLJyjTXTxVjMIwcpfncrSSEeKzG2ae+k2o5gIPvKfDsT5GPv0cctnWWY/z6xtEhWPFqn9eK44RUP/YgEw5Jt9CZLCcbkrxQoA8+xbqCvNtqd+onDcbJ25DvA99frMS4A7iaSgNQ=="},
			{input: "AVNU_OM+xPJsVvJX+yMaqQg+eR3FuWOtr5GiGJgWVzDy9WBjNMu+WEZg6bW8Lf6wL0a61yH1OUYXpBYBn7Q3wbAyC2vV75/gzwMm2Z0vk+CVYbGGPXSG7JYxgYSnqP5OBuR64bTvTcrbcRQKmI3O7IO/s7cK5XaIIqnaG626zps5TJnq0cczG2Ju5Fia7B5XTaTEXEp4SPeXljPM5Vv8cGd9cewShXzGBOxl4uDPJ/5DSqEyYBRe9BUJLOKziPNdyyqWiFdjCwFRMitRHN3RhqjTOS68v+7vVK0CdkoAGBtl19mFiHpT9E1d0brM+5P+cOGfoyZJfbNBDz2UDRkKCeI8Hws88OSKP01of9NX4KYX997WeXx0BoA=="},

			{
				input:          "AVNU_1godUWreAoJsS79OTAiX+NYm/JUdB3HVtH52IbxC8pY3UehPJ2spLAssvbXFzomt0JunKpFWApyMxgdiXHdXE6YEI7JLTRtTuYAPm0kkZsgl03iWRYSyrSkMUyQakDrBkW5hxsfZ+wZ5j5CcWB8wrJCrqu8qH7awGTSEZEHYYrz7KJJhzPJWdIH+yYyd2WO/n6XB1cOVQfLnTE3I3tj0we0PyWN064/5mvoJIQr5f+RUhzwxGcxzvk1L00QS56hgH4/b4JkB9ajnhuRArZz0UHmZEfzxdPyaRdteZ2WiP76TVtn3+PLheka2Ury1RG+P84sK4loIWtzRbqta1meWh9N1uYvGTxOU5Wigsfc8dw==",
				shouldNotMatch: true, // should not match because it is 8 bytes short
			},
		},
		"AIVEN_SERVICE_PASSWORD": {
			{input: "AVNS_XSuA-UhY_8l7n4q"},
			{input: "AVNS_uHGipSuI-sxjhYg"},
			{input: "AVNS_zSCBb-fg1m-089t"},
			{input: "AVNS_SCctNOLTRlpNoI-"},
			{input: "AVNS_xcF--Vfl9sP59XS"},
			{input: "AVNS_-d3Q03_7um-Jsk2"},
			{input: "AVNS_AAAAAAAAAAAAAAA"},
			{input: "AVNS_aaaaaaaaaaaaaaa"},
			{input: "AVNS_111111111111111"},
		},
		"ALICLOUD_ACCESS_KEY": {
			// Alibaba Cloud access key 2017
			{input: "LTAI7ylKzz4cAPkD"},
			// Alibaba Cloud access key 2019
			{input: "LTAI7ylKzz4cAPkDaBcDeFgH"},
		},
		"ALICLOUD_SECRET_KEY": {
			// Alibaba Cloud secret key
			{input: "vFkZa3r1DpyGPhGw9eCpJMVHLzgPsF"},
		},
		"AMAZON_OAUTH_CLIENT_ID": {
			{input: "amzn1.application-oa2-client.aad322b5faab44b980c8f87f94fbac56"},
		},
		"AMAZON_OAUTH_CLIENT_SECRET": {
			{input: "1642d8869b929dda3311d6c6539f2ead55192e3fc767b9071a888e60e1151cf9"},
			{
				input:          "hmac=1642d8869b929dda3311d6c6539f2ead55192e3fc767b9071a888e60e1151cf9",
				shouldNotMatch: true,
			},
			{
				input:          "sha256:1642d8869b929dda3311d6c6539f2ead55192e3fc767b9071a888e60e1151cf9",
				shouldNotMatch: true,
			},
		},
		"ASANA_LEGACY_FORMAT_PERSONAL_ACCESS_TOKEN": {
			// Token format appears to have changed in 2020: https://forum.asana.com/t/new-personal-access-token-format/88905
			{input: "0/279b6ba51a9da30b6416919d82e64ace"},
			{input: "mywebsite.com/10_0/279b6ba51a9da30b6416919d82e64ace", shouldNotMatch: true},
			{input: "279b6ba51a9da30b6416919d82e64ace.jpg", shouldNotMatch: true},
		},
		"ASANA_PERSONAL_ACCESS_TOKEN": {
			// Generated from https://app.asana.com/0/developer-console.
			// Token format appears to have changed in 2020: https://forum.asana.com/t/new-personal-access-token-format/88905
			{input: "1/1200046722087866:279b6ba51a9da30b6416919d82e64ace"},
			{input: "1/12000467220878:279b6ba51a9da30b6416919d82e64ace"},
		},
		"ATLASSIAN_API_TOKEN": {
			{input: "bKgkEpbBOxSSyoY0dhlRCAE3"},
			{input: "w91nCP2lueVBd4bq5544922E"},
		},
		"ATLASSIAN_API_TOKEN_V2": {
			{input: "ATATeyBoZWFkZXI6MSB9Cg.eyBib2R5OjEgfQo.c2lnbmF0dXJlCg30CBC1CE"},
			{input: "ATATexample_internal-token57B2EF0E"},
			{input: "ATEGeyBoZWFkZXI6MSB9Cg.eyBib2R5OjEgfQo.c2lnbmF0dXJlCgD7DC9D0F"},
			{input: "ATEGZXhhbXBsZQo1281282A"},
		},
		"AWS_KEYID": {
			{input: "AKIAI6KIQRRVMGK3WK5Q"},
			{input: "AKIAJASUCVAKYZFLWUZA"},
			{input: "AKIAJRX3QXQ6UBVAJOMQ"},
			{input: "AKIAIZKL67A5FTDDEUSQ"},
		},
		"AWS_SECRET": {
			{input: "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"},
			{input: "EXHrK3rin23Et68qjJAhp7gKMMUaqd61B0zuyXrV"},
			{input: "bSiAY3RJeZMYh+fIms/SMzX2TGvFXwDBdGkn1fDX"},
			{input: "bKiBY3RJeZMYh7fIms/SMzX2TGvFXwDBdGkn1f=="},
			{input: "dRiAY3RJeZMYh+fIms/SMzX2TGvFXwDBdGkn1fD="},
			{
				input:          "system.encryption.key.v1:dRiAY3RJeZMYh+fIms/SMzX2TGvFXwDBdGkn1fD=",
				shouldNotMatch: true,
			},
		},
		"AWS_SECRET_V2": {
			{input: "j4kaxM7TUiN7Ou0//v1ZqOVn3Aq7y1ccPh/tHTna"},
			{input: "EXHrK3rin23Et68qjJAhp7gKMMUaqd61B0zuyXrV"},
			{input: "bSiAY3RJeZMYh+fIms/SMzX2TGvFXwDBdGkn1fDX"},
			{input: "bKiBY3RJeZMYh7fIms/SMzX2TGvFXwDBdGkn1f=="},
			{input: "dRiAY3RJeZMYh+fIms/SMzX2TGvFXwDBdGkn1fD="},
			{
				input:          "system.encryption.key.v1:dRiAY3RJeZMYh+fIms/SMzX2TGvFXwDBdGkn1fD=",
				shouldNotMatch: true,
			},
		},
		"AWS_SESSION_TOKEN": {
			// From https://github.com/awslabs/amazon-kinesis-agent/blob/7b339be299f7bc74a165dfe6d3504619fa53ae9a/tst/com/amazon/kinesis/streaming/agent/tailing/pretty_printed_json#L1459
			{input: "AQoDYXdzECEagAIOzJPYTpUKU7XsIBUsTCvgdeUddG8jHk0EGwkRjNm7egkGiwlyf90ry+/USnDAirvtPCWQWKykFBSmMtfie7Pw0J4kxG+dUeImlSNFkDzFRJyZbvsnhX/H1JsW4qWWDx+N+Ah2ib/mPzwLKeRBWbuIz+gFf2ELTAARgV6fP2xfHBG50ZJccrhoxpNRfk4n9G01QjMMpyc9ZbEvmwHCdAO17vpGZ0sHBSX7YI+TchhgUYWYHSKCgclaAP4J5BXyeVGggL4ZnWLPCXOZa/nyB5wP8se+jXYNue50dJ/gOujxkAjbO9+q9pp7umbG+S8+rixUHThy0NpE0/h/bTNHdqWQINH+3bYF"},
			// From https://github.com/github/SecOps/blob/a75c2eba9052c7ee2e51118f129f8445835b7860/projects/burn_notice/awssume-post.md
			{input: "FQoDYXdzEPL//////////wEaDFQCiRl4Qo44kIUCByKSAvVyPbI4bM2uk8hHpPrdlMNsSJv/1Qkd4EInSv9W/HURYbJb/oOhz3BRjq+WFROd32ogb7N+YtW/SHiOZ2nVez1+GNyXWJEIeOBn/kvgto9RCDsfhn36anH0GhB6J9ssd31wgoFs5IvHLb5C5NbZ2CZFGxE76yf2ua69acmOzcx1VMZFZtS5x5ubNeTOUsJqEPsK7V2XG9uwFfOc30sk/MAE/MHFyfONka5yA1BzqRHqzd5q9beaBAgJsksppRwX+KpWt9+IRET22dWxaGQSIu2qssRD2guGegMDmt25k5bAkAb7Jj69jOOjdTbHqCBRbFnV7UVo5MwIZbe0pXLg8khgMi6gUTKTRoz8YaiGOcdjG0YozZ6O2gU="},
			// From https://github.com/googleapis/google-auth-library-python/blob/4e0fb1cee78ee56b878b6e12be3b3c58df242b05/tests/test_aws.py#L52
			{input: "IQoJb3JpZ2luX2VjEIz//////////wEaCXVzLWVhc3QtMiJGMEQCIH7MHX/Oy/OB8OlLQa9GrqU1B914+iMikqWQW7vPCKlgAiA/Lsv8Jcafn14owfxXn95FURZNKaaphj0ykpmS+Ki+CSq0AwhlEAAaDDA3NzA3MTM5MTk5NiIMx9sAeP1ovlMTMKLjKpEDwuJQg41/QUKx0laTZYjPlQvjwSqS3OB9P1KAXPWSLkliVMMqaHqelvMF/WO/glv3KwuTfQsavRNs3v5pcSEm4SPO3l7mCs7KrQUHwGP0neZhIKxEXy+Ls//1C/Bqt53NL+LSbaGv6RPHaX82laz2qElphg95aVLdYgIFY6JWV5fzyjgnhz0DQmy62/Vi8pNcM2/VnxeCQ8CC8dRDSt52ry2v+nc77vstuI9xV5k8mPtnaPoJDRANh0bjwY5Sdwkbp+mGRUJBAQRlNgHUJusefXQgVKBCiyJY4w3Csd8Bgj9IyDV+Azuy1jQqfFZWgP68LSz5bURyIjlWDQunO82stZ0BgplKKAa/KJHBPCp8Qi6i99uy7qh76FQAqgVTsnDuU6fGpHDcsDSGoCls2HgZjZFPeOj8mmRhFk1Xqvkbjuz8V1cJk54d3gIJvQt8gD2D6yJQZecnuGWd5K2e2HohvCc8Fc9kBl1300nUJPV+k4tr/A5R/0QfEKOZL1/k5lf1g9CREnrM8LVkGxCgdYMxLQow1uTL+QU67AHRRSp5PhhGX4Rek+01vdYSnJCMaPhSEgcLqDlQkhk6MPsyT91QMXcWmyO+cAZwUPwnRamFepuP4K8k2KVXs/LIJHLELwAZ0ekyaS7CptgOqS7uaSTFG3U+vzFZLEnGvWQ7y9IPNQZ+Dffgh4p3vF4J68y9049sI6Sr5d5wbKkcbm8hdCDHZcv4lnqohquPirLiFQ3q7B17V9krMPu3mz1cg4Ekgcrn/E09NTsxAqD8NcZ7C7ECom9r+X3zkDOxaajW6hu3Az8hGlyylDaMiFfRbBJpTIlxp7jfa7CxikNgNtEKLH9iCzvuSg2vhA=="},
			// Generated by Grey using `get_session_token` on a root account
			{input: "FwoGZXIvYXdzENz//////////wEaDGQ5L26ChbRJGrGadyJqIyNtVTM5fvnxo7Y/EsMqvu0xNfIoqnjoFJH+39/nim6UBgCr0bSblLnR0cxAtn/wK22lSryTbZ3da/zmh67zXRxDiM4WfiJNx0Dr58q5HdLFg5+UfaTLEH8Ub8TVuljrIW+lv/bdsP76+Ciou4qJBjIoie8KpODcsvTRAg/3LYYEU6SlvNvfq/gDFN71VQb/q5HZDxo8IPl+lQ=="},
		},
		"AWS_TEMPORARY_ACCESS_KEY_ID": {
			{input: "ASIAIQHG4GO7AJLYA3IA"},
			{input: "ASIAIPP3U5GUJQN7WQ6Q"},
			{input: "ASIAJ5QNCI7GMD7ZFOCQ"},
		},
		"BEAMER_API_KEY": {
			{input: "b_+F/i4GMPNTPtvu5JoKlZi7+uPIGwDk272gzRO+x2HLU="},
			{input: "b_DTBdX22+A2tyYAa55j6yCa4tnXqy/INQREVwSD8mfLM="},
			{input: "b_A8muDyx6ka/MnG3SJZsy4lYjolqwLuWA3/IuTgAEj74="},
		},
		"BITBUCKET_SERVER_PERSONAL_ACCESS_TOKEN": {
			{input: "OTEzNDY5MDAyMjE4OthQjKPe0x2+PKEOex2f/sd17CDK"},
		},
		"BLOCK_PROTOCOL_API_KEY": {
			{input: "b10ck5.e84a616cedc8822b02ac96761b068f19.91ea0c90-acee-4215-a01e-85a4438af0ea"},
		},
		"CDS_CANADA_NOTIFY_API_KEY": {
			{input: "gcntfy-github-test-revoked-10-8b1e5f58-3925-47d6-ac9c-2928a50d9c53-e7239e1a-10c4-49f3-ab89-df494ad9d743"},
			{input: "gcntfy-github-test-revoked-09-8b1e5f58-3925-47d6-ac9c-2928a50d9c53-f53b4dcd-4a0a-45d2-b197-337661f61bfd"},
			{input: "gcntfy-github-test-revoked-08-8b1e5f58-3925-47d6-ac9c-2928a50d9c53-7604ef0d-efb1-47e3-98c9-14f523b52a6c"},
			{input: "gcntfy-github-test-revoked-07-8b1e5f58-3925-47d6-ac9c-2928a50d9c53-22ee6ab5-bf58-437c-b5dc-0f4ff30e82a8"},
			{input: "gcntfy-github-test-revoked-06-8b1e5f58-3925-47d6-ac9c-2928a50d9c53-ee4ac5d1-34a6-4fa2-8ec5-b165a17d3e16"},
			{input: "gcntfy-github-test-revoked-05-8b1e5f58-3925-47d6-ac9c-2928a50d9c53-5c86582a-e416-4770-8142-99d9103ac4e3"},
			{input: "gcntfy-github-test-revoked-04-8b1e5f58-3925-47d6-ac9c-2928a50d9c53-42d031b0-8281-401e-a736-281b7678bbd0"},
			{input: "gcntfy-github-test-revoked-03-8b1e5f58-3925-47d6-ac9c-2928a50d9c53-4a9f7a79-598e-49f1-b366-b91583cff4a6"},
			{input: "gcntfy-github-test-revoked-02-8b1e5f58-3925-47d6-ac9c-2928a50d9c53-1a31a99c-e213-453d-929a-6da0c58680d5"},
			{input: "gcntfy-github-test-revoked-01-8b1e5f58-3925-47d6-ac9c-2928a50d9c53-8fcaba28-922d-4612-b361-9dfbb3ba8fbb"},
			// max length
			{input: "gcntfy-plqh2gh1j2293rj4v2zj40h10v7mxkh8r5uvod-_ventgmz0ubu16myocuemoo_42hnctgg0ykkil2nxptspjsj1g2j6v4snp0mtdeplppep1f-iseqnbcudqm05qgd-7w1j143o9ckpy4k0pih6by8abklutq7c9a3083t68bc13puefzthlat1_7lbto828biaiq-1r08ribzbjrdjaltuj63br8e08_mpsw2y1u474p4izk6ffcj8c-1sxhx-8b1e5f58-3925-47d6-ac9c-2928a50d9c53-8fcaba28-922d-4612-b361-9dfbb3ba8fbb"},
		},
		"CHECKOUT_PRODUCTION_SECRET_KEY": {
			{input: "sk_062a30c2-c681-4ae7-9521-9e7eb84478c3"},
		},
		"CHECKOUT_PRODUCTION_SECRET_KEY_WITH_CHECKSUM": {
			{input: "sk_23t3lfdls2s2yytgb6jhvv4szm6"},
		},
		"CHECKOUT_TEST_SECRET_KEY": {
			{input: "sk_test_062a30c2-c681-4ae7-9521-9e7eb84478c3"},
		},
		"CHECKOUT_TEST_SECRET_KEY_IN_PRODUCTION": {
			{input: "sk_test_062a30c2-c681-4ae7-9521-9e7eb84478c3"},
		},
		"CHECKOUT_TEST_SECRET_KEY_WITH_CHECKSUM": {
			{input: "sk_sbox_23t3lfdls2s2yytgb6jhvv4szm6"},
			{input: "sk_sbox_bpbu2csoqb5hp7liux3i5vl6fi#"},
		},
		"CHIEF_TOOLS_TOKEN": {
			{input: "ctp_nN6MS3Qa2gqDtGeH5sVv2eupP53H5B4LBz4g"},
		},
		"CLEARBIT_API_KEY": {
			{input: "sk_1da939ade2c7d213ca1eb892ac24ffe5"},
			{input: "sk_fa6cb164dc2a2736cfca41a99ba7c60a"},
		},
		"CLOJARS_DEPLOY_TOKEN": {
			{input: "CLOJARS_55caac69f43c796b63a772a1291965625d786538f22df961766827577027"},
			{input: "CLOJARS_770584d592da432850a9f48df2afba5dde4410ac13624acef38e9ba05dc2"},
			{input: "CLOJARS_5c59d1cfb2995aa94620e712b27b11fc236a2abcca2d0a32a1ccf69149cb"},
		},
		"CODESHIP_GENERIC": {
			{input: "codeship_username"},
			{input: "codeship-user"},
			{input: "codeship_api_key"},
			{input: "codeship-api-username"},
			{input: "codeship-aes-key"},
		},
		"COMPOSER_LOCK_CONTENT_HASH": {
			{
				input:   "   \"content-hash\": \"d90cae3a04ccf677e810d3391ec018b9\",",
				matches: []string{"\"content-hash\": "},
			},
		},
		"COMPOSER_LOCK_SHASUM": {
			{
				input:   "   \"shasum\": \"f832b04a5158645330d29bdb7265652dbcb6e4c3\",",
				matches: []string{"\"shasum\": "},
			},
		},
		"COMPOSER_LOCK_REFERENCE": {
			{
				input:   "   \"reference\": \"98c313c831e5d99bb393ba1844df91bab2bb5b8b\",",
				matches: []string{"\"reference\": "},
			},
		},
		"COMPOSER_LOCK_DIST_URL": {
			{
				input:   "   \"url\": \"https://api.github.com/repos/FriendsOfPHP/PHP-CS-Fixer/zipball/1023c3458137ab052f6ff1e09621a721bfdeca13\",",
				matches: []string{"\"url\": \"https://api.github.com/repos"},
			},
		},
		"CONTENTFUL_PERSONAL_ACCESS_TOKEN": {
			// Generated from https://app.contentful.com/account/profile/cma_tokens
			{input: "CFPAT-60pph60q1cLL3Okio2Ek0Ze1yTCD_rtB3QMF8mSgNIY"},
			{input: "CFPAT-PI4L1bXAJwgRvjU_cvLmegPC8"},
		},
		"CONTRIBUTED_SYSTEMS_CREDENTIALS": {
			{
				input:   "contribsys_credentials = 'f231abd5:86f0be99'",
				matches: []string{"f231abd5:86f0be99"},
			},
		},
		"CONTRIBUTED_SYSTEMS_NAME_PRESENCE": {
			{input: "contribsys"},
			{input: "CONTRIBSYS"},
			{input: "ContribsysCredentials", matches: []string{"Contribsys"}},
		},
		"CRATESIO_API_TOKEN": {
			// Generated from https://crates.io/me
			{input: "cioMbVekg9CmmT8SXhgR3FgdQXDdKBoD2zJ"},
			{
				input:          "AgronegócioBrasiliaDANTNwNTAwNTAwNTA3Centro",
				shouldNotMatch: true,
			},
		},
		"DATABRICKS_API_TOKEN": {
			{input: "dapideadbeefdeadbeefdeadbeefdeadbeef"},
			{input: "dapideadceefdeadbeefdeadbeefdeadbeef"},
		},
		"DATADOG_NAME_PRESENCE": {
			{input: "datadog"},
			{input: "DATADOG"},
			{input: "Datadog"},
			{input: "DD_APP_KEY"},
			{input: "dd_api_key"},
			{input: "DD_API_KEY"},
			{input: "DD-API-KEY"},
			{input: "DD-APPLICATION-KEY"},
			{
				input:   "https://api.datadoghq.com/api/v1/dashboard",
				matches: []string{"datadoghq"},
			},
		},
		"DATADOG_API_KEY": {
			{input: "775c328eee96116861a8451d93047952"},
			{input: "354f1b87198372cfe8fbcdd9ce7f30d8"},
			{input: "f631a71273a23f5865d3349616f45107"},
		},
		"DATADOG_APP_KEY": {
			{input: "6f3584d1b6aae5f0dca08ca99cf752d93de3055b"},
			{input: "a61a4c0858e4374c926b742e675aa4e1d5053a37"},
			{input: "54449a91d15b474ecbb57c63fd006f62de9b4e12"},
		},
		"DATADOG_RCM": {
			{input: "DDRCM_QPCAG33SM7HAAAAAALCAEZDDVR2XGMJOOBZG6ZBOMRXWPRADNNSXTWJIMM4TKNRUHA3TQODDMY3TKMDBG44TOMJUMQ4DSMJUMQZDGZBQGUZWKZDBGRRWCZJQ"},
			{input: "DDRCM_QPCAG33SM7HAAAAAALCAEZDDVR2XGMJOOBZG6ZBOMRXWPRADNNSXTWJIGBRTSYLGGZRDANLFMFQWEMZSHBSGKYZZMUYWKMTEMIYDINZRMI3TSNZVMJTDSM3F"},
			{input: "DDRCM_QPCAG33SM7HAAAAAALCAEZDDVR2XGMJOOBZG6ZBOMRXWPRADNNSXTWJIGFTGGZRSMIYGENLGGNTGGZTBMY2TCNRZG5SDOMBVGFRWMMLGGUYTKNRQGBTGCNJS"},
		},
		"DEVCYCLE_CLIENT_API_KEY": {
			// provided
			{input: "dvc_client_5dd5d34d_bdd6_42c3_809e_29a111480456_4f4e167"},
			// valid for other devcycle types
			{
				input:          "dvc_mobile_a1e0b52a_9031_4e25_8a67_094ce28aac49_74d9ee4",
				shouldNotMatch: true,
			},
			{
				input:          "dvc_server_6d311ab9_c8c5_4122_938b_4f97d2d1545b_a75165e",
				shouldNotMatch: true,
			},
		},
		"DEVCYCLE_MOBILE_API_KEY": {
			{input: "dvc_mobile_a1e0b52a_9031_4e25_8a67_094ce28aac49_74d9ee4"},
			// valid for other devcycle types
			{
				input:          "dvc_client_5dd5d34d_bdd6_42c3_809e_29a111480456_4f4e167",
				shouldNotMatch: true,
			},
			{
				input:          "dvc_server_6d311ab9_c8c5_4122_938b_4f97d2d1545b_a75165e",
				shouldNotMatch: true,
			},
		},
		"DEVCYCLE_SERVER_API_KEY": {
			{input: "dvc_server_6d311ab9_c8c5_4122_938b_4f97d2d1545b_a75165e"},
			// valid for other devcycle types
			{
				input:          "dvc_client_5dd5d34d_bdd6_42c3_809e_29a111480456_4f4e167",
				shouldNotMatch: true,
			},
			{
				input:          "dvc_mobile_a1e0b52a_9031_4e25_8a67_094ce28aac49_74d9ee4",
				shouldNotMatch: true,
			},
		},
		"DIGITALOCEAN_OAUTH_TOKEN": {
			{input: "doo_v1_4ea90994efe8999d0892b6069bc754a78c656f8e843361e1c4d1cd04ac85c388"},
		},
		"DIGITALOCEAN_PERSONAL_ACCESS_TOKEN": {
			{input: "dop_v1_ae5067bb5c1d3bcb1f9e580f7a8dd56186f27791101ccc32bd942c8eb9247901"},
		},
		"DIGITALOCEAN_REFRESH_TOKEN": {
			{input: "dor_v1_d6ce4b93106021c47be0b580e9296453ef2f319b02b5513469f0ec72d99af2e2"},
		},
		"DIGITALOCEAN_SYSTEM_TOKEN": {
			{input: "dos_v1_7b0161c8ebf811ebb7057fdb8dab0fa0877dc27aebf811ebb32cc380f57d2d6d"},
		},
		"DISCORD_API_TOKEN": {
			// shortest possible discord api token
			{input: "MTk4NjIyNDgzNDcxOTI1MjQ.Cl2FMQ.ZnCjm1XVW7vRze4b7Cq4se7kKWs"},
			// longest possible discord api token
			{input: "MTk4NjIyNDgzNDcxOTI1MjQ4MTI0.Cl2FMQ3.ZnCjm1XVW7vRze4b7Cq4se7kKWs"},
			// includes dashes
			{input: "MTk4NjIyNDgzNDcxOTI1MjQ4MTI0.Cl-FMQ3.ZnCjm1XVW7vRze4-7Cq4se7kKWs"},
			// includes underscores
			{input: "MTk4NjIyNDgzNDcxOTI1MjQ4MTI0.Cl2F_Q3.ZnCjm_XVW7vRze4b7Cq4se7kKWs"},
		},
		"DISCORD_API_TOKEN_V2": {
			{input: "ODE3NjEwMjM3NTM5MjU0MzAz.G23uq8.MNsZ-qB6So5FuMk0Bj-du_oGg3XXuE6c3hJ3T4"},
			{input: "MTk4NjIyNDgzNDcxOTI1MjQ.Cl2FMQ.ZnCjm1XVW7vRze4b7Cq4se7kKWsa"},
			// Last part of the token is capped at 4096
			{input: fmt.Sprintf("ODE3NjEwMjM3NTM5MjU0MzAz.G23uq8.%s", strings.Repeat("a", 4097)), shouldNotMatch: true},
			// Shouldn't match tokens detected with the v1 regex
			{input: "MTk4NjIyNDgzNDcxOTI1MjQ.Cl2FMQ.ZnCjm1XVW7vRze4b7Cq4se7kKWs", shouldNotMatch: true},
		},
		"DOCKER_SWARM_JOIN_TOKEN": {
			// Taken from https://docs.docker.com/engine/reference/commandline/swarm_join-token/#examples
			{input: "SWMTKN-1-3pu6hszjas19xyp7ghgosyx9k8atbfcr8p2is99znpy26u2lkl-b30ljddcqhef9b9v4rs7mel7t"},
		},
		"DOCKER_SWARM_UNLOCK_KEY": {
			// Taken from https://docs.docker.com/engine/swarm/swarm_manager_locking/#view-the-current-unlock-key-for-a-running-swarm
			{input: "SWMKEY-1-8jDgbUNlJtUe5P/lcr9IXGVxqZpZUXPzd+qzcGp4ZYA"},
		},
		"DOPPLER_PERSONAL_TOKEN": {
			{input: "dp.pt.SM9IkgP9n3UdOCiW2m6iLnGIS9rEKUM9X1kwiUSv"},
			{input: "dp.pt.SM9IkgP9n3UdOCiW2m6iLnGIS9rEKUM9X1kwiUSvXa1"},
			{input: "dp.pt.SM9IkgP9n3UdOCiW2m6iLnGIS9rEKUM9X1kwiUSvXa12"},
		},
		"DOPPLER_SERVICE_TOKEN": {
			{input: "dp.st.dev-1.5iSgsylLUh1V8gWGbwbWbO8SHSxs3wkdkYAYE3Ik"},
			{input: "dp.st.dev_1.5iSgsylLUh1V8gWGbwbWbO8SHSxs3wkdkYAYE3Ik123"},
			{input: "dp.st.dev.5iSgsylLUh1V8gWGbwbWbO8SHSxs3wkdkYAYE3Ik1234"},
		},
		"DOPPLER_CLI_TOKEN": {
			{input: "dp.ct.Hz53zCklAAldpZywPRaXPaaYlABB1HOrKgtvyhLG"},
			{input: "dp.ct.Hz53zCklAAldpZywPRaXPaaYlABB1HOrKgtvyhLG123"},
			{input: "dp.ct.Hz53zCklAAldpZywPRaXPaaYlABB1HOrKgtvyhLG1234"},
		},
		"DOPPLER_SCIM_TOKEN": {
			{input: "dp.scim.IcgO4od2ONhDCys8tELOouUK9RSDCevePjks0ymo"},
			{input: "dp.scim.IcgO4od2ONhDCys8tELOouUK9RSDCevePjks0ymo123"},
			{input: "dp.scim.IcgO4od2ONhDCys8tELOouUK9RSDCevePjks0ymo1234"},
		},
		"DOPPLER_AUDIT_TOKEN": {
			{input: "dp.audit.BcgO4od2ONhDCys8tELOouUK9RSDEevePjks0ymo"},
			{input: "dp.audit.TA24lazmVitK8R3tyrtjPDsUaacTyHqxMnpMatec"},
			{input: "dp.audit.TA24lazmVitK8R3tyrtjPDsUaacTyHqxMnpMatec123"},
			{input: "dp.audit.TA24lazmVitK8R3tyrtjPDsUaacTyHqxMnpMatec1234"},
		},
		"DOPPLER_SERVICE_ACCOUNT_TOKEN": {
			{input: "dp.sa.bAqhcVzrhy5cRHkOlNTc0Ve6w5NUDCpcutm8vGE9myi"},
		},
		"DEFINED_NETWORKING_NEBULA_API_KEY": {
			{input: "dnkey-SYCIIXJLXD4N4QXCFJF2LGECNM-NCMJKZD6RJT5B2EN5IOJI466K63LCHSFC75DUQMVTDUI7HCCLJFQ"},
			{input: "dnkey-F3DLE5I3UJVGZ3JHSD3LWWEL4I-IFVUISXDUZAPRRXI5VIEXW4TLZ4GU3PQRVVRYDCHYHBXLNVVQ3TQ"},
			{input: "dnkey-RSEHC4ERQCDMCURAZO4CV2II2U-S4SHTMRBSBKFUPIUUCUQHQCPZZHYV3XLDXG7FVNO3QZLMJZ7T3GA"},
			{input: "dnkey-UPO26YESG7QKHMEOGB324W4STQ-4TL6DG5ZYMU565EANGLV7XEM624LOZGQLXZFXFR2LZ6WU5QQLHLQ"},
			{input: "dnkey-UXEFCN63OPKU7S47DS4KH5U3NY-ZDDDYLDTTCXP3UTNAMJBDSOUQVYUAQPLMMZAQNAWRFNBLZ6PSO4A"},
		},
		"DROPBOX_OAUTH2_ACCESS_TOKEN": {
			{input: "nBvyMYh4P7AAAAAAAAAAkHvHxbBAE3R1Jd7sJh2rWbPCk85-9Dm4UCvYtMnze1BY"},
			// token with underscore
			{input: "nBvy_Yh4P7AAAAAAAAAAkHvHxbBAE3R1Jd7sJh2rWbPCk85-9Dm4UCvYtMn_e1BY"},
		},
		"DROPBOX_OAUTH2_SHORT_LIVED_ACCESS_TOKEN": {
			// shortest possible token
			{input: "sl.dDkEmoXPeGClikULARyQMz4FQVwAgthNykAfnVrZPRMnYeE8jeuYowEHtt8Hga6YDz3Oxl-BrILAzd-I5ax88uWSlO7UAz5WKXKq52Z645CnSe2RVplxjQJIIlSBm7f4jcLiHxcb"},
			// longest possible token
			{input: "sl.uVLQiXtw5ze1ckBS7pxda5vFSzC7DRSwhF2BxzHNBJW8gcl-oPd4cOoKvncPGk1rTOiDstOGVlCN1ZuMQU-IZoGY9mm7jOrrXxcO5voPcnVvu1GbxshWKEFfdmF0DLssrdIGlvrxYBvSiEFLrKbmxf7HSdqOCRLmbJgS4bsd7-RKujFtNmOyQUUglmmKjO1qUe8Mk6dA"},
			// token that exceeds the 200 char limit should not match
			{
				input:          "sl.uVLQiXtw5ze1ckBS7pxda5vFSzC7DRSwhF2BxzHNBJW8gcl-oPd4cOoKvncPGk1rTOiDstOGVlCN1ZuMQU-IZoGY9mm7jOrrXxcO5voPcnVvu1GbxshWKEFfdmF0DLssrdIGlvrxYBvSiEFLrKbmxf7HSdqOCRLmbJgS4bsd7-RKujFtNmOyQUUglmmKjO1qUe8Mk6dAI5ax88uWSlO7UAz5WKXKq52Z",
				shouldNotMatch: true,
			},
			// token with underscore
			{input: "sl.dDkEmoXPeGClikULARyQMz4FQVwAgthNykAfnVrZPRMnYeE8jeuYowEHtt8Hga6YDz3Oxl-BrILAzd-I5ax88uWSlO7UAz5_KXKq52Z645CnSe2RVplxjQJIIlSBm7f4jcLiHxcb"},
		},
		"DUFFEL_LIVE_ACCESS_TOKEN": {
			{
				input:   "Bearer duffel_live_Q3L4Xh0p7Qj77h4tBJVdjUews3E8bdxkVcq7IGVWHk_",
				matches: []string{"duffel_live_Q3L4Xh0p7Qj77h4tBJVdjUews3E8bdxkVcq7IGVWHk_"},
			},
		},
		"DUFFEL_TEST_ACCESS_TOKEN": {
			{
				input:   "Bearer duffel_test_Hzf2Daqe_i-TWBJOd4b9lAcpaOUMkJSOe1U9qj_4sJy",
				matches: []string{"duffel_test_Hzf2Daqe_i-TWBJOd4b9lAcpaOUMkJSOe1U9qj_4sJy"},
			},
		},
		"DYNATRACE_INTERNAL_TOKEN": {
			{input: "dt0s01.RFNYASDL.5FJWNDTUXJ6PKHEHDDVKXV2K73ZDGWUFS6GKHGAFKE2DUG3JYCFXJUAGLXTN6ENX"},
		},
		"DYNATRACE_API_TOKEN": {
			{input: "dt0c01.ST2EY72KQINMH574WMNVI7YN.G3DFPBEJYMODIDAEX454M7YWBUVEFOWKPRVMWFASS64NFH52PX6BNDVFFM572RZM"},
		},
		"DYNATRACE_ODIN_AGENT_TOKEN": {
			{input: "dt0a01.ay34c71d.3a1ebe3ad61fc485286e185b4e08061acda1c4f51a6ade178925cb1055ecd2c2"},
		},
		"EASYPOST_PRODUCTION_API_KEY": {
			{input: "EZAK7be75611a6bc49f18cbae67dc0929ecckEDkWHN7VUnxO7CZpgauOg"},
		},
		"EASYPOST_TEST_API_KEY": {
			{input: "EZTK7be75611a6bc49f18cbae67dc0929ecc8PLls9UoF4o9ROv38PCE1w"},
		},
		"EBAY_PRODUCTION_CLIENT_ID": {
			{input: "Ex4mple-MyAppN4m-PRD-05d7504c4-7e62e952"},
		},
		"EBAY_PRODUCTION_CLIENT_SECRET": {
			{input: "PRD-26de56b6367d-60a1-4810-a224-af9e"},
		},
		"EBAY_SANDBOX_CLIENT_ID": {
			{input: "AnEx4mpl-MyAppN4m-SBX-05d7504c4-7e62e952"},
		},
		"EBAY_SANDBOX_CLIENT_SECRET": {
			{input: "SBX-26de56b6367d-60a1-4810-a224-af9e"},
		},
		"ELEPHANTSQL_POSTGRES_CONNECTION_URL": {
			{input: "postgresql://sxsaomad:sA1zCGuGRz_-I2YOvSnA3mXk1dza9V5w@chunee.db.elephantsql.com/sxsaomad"},
			{input: "postgres://xbteacie:bk597m23TvaONLrOlFhIhJcLlV27AM7X@tuffi.db.elephantsql.com:5432/xbteacie"},
			{input: "postgres://xbteacie:bk597m23TvaONLrOlFhIhJcLlV27AM7X@horton.elephantsql.com:5432/xbteacie"},
		},
		"EVERVAULT_API_KEY": {
			// Generated from https://app.evervault.com/
			{input: "MTI4Ng==:4VA39JETYAcDFVImljKPn1stisWY6eB6LKomGN109AIE3dd62lFVqTAK7t9wLMVUY"},
			{input: "NzE1:aztxQDkXeR51CVJYzckxoPXdvfRrZ6U38Kd6GEXAN4yk7Na6RQwMA5sAIAbmmOBf"},
		},
		"FACEBOOK_VERY_TINY_ENCRYPTED_SESSION": {
			{input: "EAABsbCS1iHgBAPo76dBNbLYf0HHZBCfnJqDRsPRdjRzGEWIknCplflQMMJ5NavjMcYHqR45ON9ZCLLH8ftRBd9qzBWLjT0975NrEwUZAjbQYAUT8PrFZBzRU9UuAO0E5gH4XzWOvmsZBIHuJqEikm90pePjassfyZBywSj1IMR5gZDZD"},
			{input: "EAAAAUaZA8jlABAJ8M73U2swglqzO1BBLy5PZAqTaeURZCPKh8piT7zWdycznesmlZCVnK8UlvDizZCr3OgMbmL6Sh02L4iZAntHL90sXPbm6ZApXSFYKz8NwxnsbFg7RiQAImsGyqmHKzOlOdxZAJFyxcsQZBn2JG66mBEGO2w9TeHAZDZD"},
			// Taken from a website, not provided by partner
			{input: "EAAECKEsf4G4BAGQaE4yA1basdfxxxJSUQ2HS7fUllXQj5V1jdZAykykbVMmnJ8kiiVyGTU4Spj6emBFz0mZBRlNtaJwJGhChCquYRSZBb7vmsfl64jhy7QUo54SesKZATXKYa2jDHzQDWedXjWVTbmM4pvtbsai63jgZA16iCDHKb"},
		},
		"FASTLY_API_TOKEN": {
			// Generated from https://manage.fastly.com/account/personal/tokens
			{
				input:   "fastly_api_key = 'iwfWJpOBxdrqLQHf3ptb-CtK2MkakgFA'",
				matches: []string{"iwfWJpOBxdrqLQHf3ptb-CtK2MkakgFA"},
			},
		},
		"FASTLY_LEGACY_API_KEY": {
			{
				input:   "fastly_api_key = '775c328eee96116861a8451d93047952'",
				matches: []string{"775c328eee96116861a8451d93047952"},
			},
		},
		"FIGMA_PAT": {
			{input: "figo_bhxIa3DcGWg4Ngm2s6vU_aBBfEu365dWZrEedNyt"},
			{input: "figu_kYj5Aw5rNcyJ5QOAxiG9tFHwvKJFZxhL2nzuVtfu"},
			{input: "figd_NCmlNcGcrU327xAz_xPmjD3jHi2jNwmXUTO085a7"},
			{input: "figd_LZIelGtvwY_eclRrATg6dpUTzQ7BLBxuce6NVCmR"},
			// Modifed tokens supplied by Figma to fully test pattern
			{input: "figor_bhxIa3DcGWg4Ngm2s6vU_aBBfEu365dWZrEedNyt"},
			{input: "figur_LZIelGtvwY_eclRrATg6dpUTzQ7BLBxuce6NVCmR"},
			{input: "figuh_kYj5Aw5rNcyJ5QOAxiG9tFHwvKJFZxhL2nzuVtfu"},
			{input: "figoh_NCmlNcGcrU327xAz_xPmjD3jHi2jNwmXUTO085a7"},
			// Should not match
			{input: "figon_bhxIa3DcGWg4Ngm2s6vU_aBBfEu365dWZrEedNyt", shouldNotMatch: true},
			{input: "figuz_LZIelGtvwY_eclRrATg6dpUTzQ7BLBxuce6NVCmR", shouldNotMatch: true},
			{input: "figut_kYj5Aw5rNcyJ5QOAxiG9tFHwvKJFZxhL2nzuVtfu", shouldNotMatch: true},
			{input: "figoq_NCmlNcGcrU327xAz_xPmjD3jHi2jNwmXUTO085a7", shouldNotMatch: true},
		},
		"FINICITY_APP_KEY": {
			{
				input:   "curl 'https://api.finicity.com/aggregation/v2/partners/authentication'\n--header 'Accept: application/json'\n--header 'Content-Type: application/json'\n*--header 'Finicity-App-Key: 604dacc04fd473c50d3766ded9f31b1f'* \n--data-raw '{\"partnerId\": \"<redacted>\", \"partnerSecret\": \"<redacted>\"}",
				matches: []string{"604dacc04fd473c50d3766ded9f31b1f"},
			},
			{
				input:   "define(\"__FINICITY_API_KEY__\", \"448f936b64c14ee514cfe101055d6bfc\"}",
				matches: []string{"448f936b64c14ee514cfe101055d6bfc"},
			},
			{
				input:   "Finicity-App-Key' : '4d003c112e66263b9dec7a3dbfa9b5f5",
				matches: []string{"4d003c112e66263b9dec7a3dbfa9b5f5"},
			},
			{
				input:   "finicity.app.key=6f9d1550391d7f92a45837f43ce2f33e",
				matches: []string{"6f9d1550391d7f92a45837f43ce2f33e"},
			},
		},
		"FIREBASE_CLOUD_MESSAGING_SERVER_KEY": {
			{input: "AAAABX4G4Ew:APA91bGJFS0AfW_5-_fMGzo3dmz1OaUYlw2RE6-9ldI_M85zV9gJz_t-QLmRdnN6Sn0e45EaeIwAcYRVuu9QCjDGurTIR3UEUz7yp8gW08KHeKCOrpQXXhw9-XnZU4bH_9JxL3ubmFI6"},
			{input: "AAAABX-G_Ew:APA91bGJFS0AfW_5-_fMGzo3dmz1OaUYlw2RE6-9ldI_M85zV9gJz_t-QLmRdnN6Sn0e45EaeIwAcYRVuu9QCjDGurTIR3UEUz7yp8gW08KHeKCOrpQXXhw9-XnZU4bH_9JxL3ubmFI6"},
		},
		"FLUTTERWAVE_LIVE_API_SECRET_KEY": {
			// Generated at https://dashboard.flutterwave.com/dashboard/settings/apis
			{input: "FLWSECK-998d460b7f1c512ac115079d5daa016f-X"},
			{input: "FLWSECK-7e4d32ad93701db232526ecf4b79b9ed-X"},
		},
		"FLUTTERWAVE_TEST_API_SECRET_KEY": {
			{input: "FLWSECK_TEST-0a1fd4f613a38e6e846943b081e1b94b-X"},
			{input: "FLWSECK_TEST-879ade220178281c1189ccd95a665722-X"},
		},
		"FRAMEIO_THIRD_PARTY_DEVELOPER_TOKEN": {
			{input: "fio-u-NdqDfjg_JLNGLe3mbpY5Vx3Tn8MpkzpM_1Ra8LAswHGnMaNfUe62T_4Qshncd_fI"},
		},
		"FULLSTORY_API_KEY": {
			{input: "M0dEL2dyZXlzdGVpbEBnaXRodWIuY29tOtymS7ZvPk/1vXuHxy4OMql11T+UsPDVNDY5kHA594oJ/KM48G1D"},
			{input: "M0dEL2dyZXlzdGVpbEBnaXRodWIuY29tOtymS7ZvPk/1vXuHxy4OMql11T+UsPDVNDY5kHA594oJLg==/KM48G1D"},
		},
		"FULLSTORY_API_KEY_LEGACY": {
			{input: "RTFBUlo6RWUybEUxcXBtbjJFNkRaejlERE5EbGltanlLcTNTRDdsYWFXWFMzVEdocz01"},
			{input: "RTFBUlo6RWUybEUxcXBtbjJFNkRaejlERE5EbGltanlLcTNTRDdsYWFXWFMzVEdocz0="},
			{input: "RTFBUlo6RWUybEUxcXBtbjJFNkRaejlERE5EbGltanlLcTNTRDdsYWFXWFMzVEdocz=="},
			{input: "RTFBUlo6RWUybEUxcXBtbjJFNkRaejlERE5EbGltanlLcTNTRDdsYWFXWFMzVEdocz=="},
			{input: "RTE6RWUybEUxcXBtbjJFNkRaejlERE5EbGltanlLcTNTRDdsYWFXWFMzVEdocz0="},
		},
		"GITHUB": {
			{input: "f3cadbc97629b0aaac9ecabaa0f661456042de6c"},
			{input: "E7F25C2CF921D8E3F2BED1662EC10C2C2BA50712"},
		},
		"GITHUB_APP_TOKEN": {
			{input: "v1.56857379b36d85f702a1063a8d68d1d34a810a30"},
			{input: "v1.f3cadbc97629b0aaac9ecabaa0f661456042de6c"},
			{input: "v1.E7F25C2CF921D8E3F2BED1662EC10C2C2BA50712"},
		},
		"GITHUB_TOKEN_V2": {
			{input: "gh1_1777777Y0hijklmnopqrs_0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefgEC7K7TLFtuvwxyz0"},
			{input: "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"},
		},
		"GITHUB_PERSONAL_ACCESS_TOKEN": {
			{input: "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"},
		},
		"GITHUB_OAUTH_ACCESS_TOKEN": {
			{input: "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"},
		},
		"GITHUB_USER_TO_SERVER_TOKEN": {
			{input: "ghu_iJxyu4JkSaVUS1EVBmaok0YAl56uLr3ipY7B"},
		},
		"GITHUB_SERVER_TO_SERVER_TOKEN": {
			{input: "ghs_iJxyu4JkSaVUS1EVBmaok0YAl56uLr3ipY7B"},
		},
		"GITHUB_REFRESH_TOKEN": {
			{input: "ghr_8nCjGaHwmLS1wgks9y66hLnLlHMfKA6exMVhXXyavMMO0fEl3YxMvv2skLJUCT3UMSpysr2VKOni"},
		},
		"GITHUB_TEST": {
			{input: "GITHUB_TEST_TOKEN_f3cadbc97629b0aaac9ecabaa0f661456042de6c"},
			{input: "GITHUB_TEST_TOKEN_E7F25C2CF921D8E3F2BED1662EC10C2C2BA50712"},
		},
		"GITHUB_CREDENTIALS_IN_URL": {
			{
				input:   "https://greysteil:not-secure@github.com",
				matches: []string{"greysteil:not-secure"},
			},
			{
				input:   "http://my-username:p@$$word1@github.com",
				matches: []string{"my-username:p@$$word1"},
			},
		},
		"GITHUB_SSH_PRIVATE_KEY": {
			{input: "-----BEGIN RSA PRIVATE KEY-----\nMIIEpQIBAAKCAQEAr/6xOgVzKS5UWluWl19TCWILfJvVlnAFcwh7KyA1GWy/mhF9\nfiyrj1j9Yt9S1fmVk1CZLPTsQYrnAGVNrwJYHy1B44XyOyFcNLaiT6sB+wC91lps\nUfGRfXa1L7fsUtJCxB+7PBHP+kbMqw498QBwjPJEZsIIUvnXLFdgh3YpWDHutyXo\npN0U4WJin5+F5uMMSHzng0N9Xjvcw96pYWKk8wpICtaKLZqVA9Dbli/y3Hak//1e\n1N3Eh1Eo7eEvTJLVporyiM1G6WjtfAb2cbYXrd8BxLAyS3KuhdiMsPs2VPJnuVYC\nzQencUxi+xJGQkqvqjyADT1VVdhwudCFYUmoXQIDAQABAoIBADNEezYOrlxZraLg\nuT6BOzwpfnUfJBn9qei3mMGYUT+FyU7FN4xQ0O0iHDX4HjZMzUCrouNQuZ3iK6aW\n3AlWInt6gI4Zz9Vfw29roF6azyniLmrJznIUb7BfqyoqZsI9k8tz/uPhwHcEtsxB\nitOwsBiu3jQc47XgJ8k37tunFSYmcWoTkBox9FJoA4w7cHL5rSbHpYMv4pd5oV/9\n/Uwm/Im4G9Pij1gY6jLGyXMybLuAlB3ZcMEV4X+O7jgrmd8jvIZp+A66viOyqK8U\nTogeBXlmMDeuyV5yAGjxWJI3OqJey6qEQfh7zq6XGWLwhC+8pyjgd8xrERy3p/JL\n/Jb+pUECgYEA5xCGli1pUG8guvp6iwXKmsgNBaNsOtVqHgb0um1InHAsfRslpM38\nDeHrC5gD4DOoSioVgbHF7ppqHpEh41MbzJWfdSPhAVoBIUZiD/jFTnAiird48+3F\nnKFIv6NULyFy/z1Y0cjrcEkjJSCrlqKPKPZzdBfrBrNDS8w2YMTVitECgYEAwvzK\ntnbVqbP4wvvSyMamfPKAKFEGV+5dvelf61uecUGlwrrTYc3y5W6PThUM5ZdXwNXp\nYmgaY5coGy0o1CM6MBJ7bx4Aw1ygZNbrer+guUPNQkKjl2NiLhSLRm2ga1XAysxd\nyWQm2NDlMFzZgnGvxHj5+AGsZfGRQpBMzHwDT80CgYEAiIszfTuIqIeDB/tMvyrE\n94KQb2yLYJkNBIGHzUMXTZrcL3IDZMh00p9WjptebvcX0/vaibHMDZwiab3KENPj\n8ZnZiReSt4HAeTFmcZnIvvl08BRL3Zn81PpaSyTxcoiJtFtESXQ57TjLE/2iaHnX\nr5Uz1L7tnCAC/J/I4pZuuoECgYEAiQAS8hcW0rDYBS/ojxc8XSgJscoUOe4KQWha\n88Qg1BS7AdJAuUR5+Igw+jzCHgKzLpNd8r2QZQ8Mp+OX/01tEd+6iH09LgbDz3ZO\nZ6WCqQkhi//Eb5btodDfdrGJ+EB9QEBNWTYcMVS847kpPoTgaZxSjdWnKs2LMYiv\n3TD5JrUCgYEAxpZQkT7VA1loPCjZosplW+dvNQFxBaO4nKKVgOlWrkitdi6MtRPC\n5I9+hPaBBr6puNq7MyRBrlgafYSh5GiayUg4rWZZuQbTtKsWGxvyqk/Eh9FQ2uK0\nkGurKO91ZZetoaQIYvml3lAaufFZmZhLWK07dFQyOadvn6hVouQF8KU=\n-----END RSA PRIVATE KEY-----"},
			{
				// Ensure that we only capture the private key and not some surrounding armored PEM data.
				input: "-----BEGIN CERTIFICATE-----\nMIIEpQIBAAKCAQEAr/\n-----END CERTIFICATE-----\n-----BEGIN RSA PRIVATE KEY-----\nMIIEpQIBAAKCAQEAr/6xOgVzKS5UWluWl19TCWILfJvVlnAFcwh7KyA1GWy/mhF9\nfiyrj1j9Yt9S1fmVk1CZLPTsQYrnAGVNrwJYHy1B44XyOyFcNLaiT6sB+wC91lps\nUfGRfXa1L7fsUtJCxB+7PBHP+kbMqw498QBwjPJEZsIIUvnXLFdgh3YpWDHutyXo\npN0U4WJin5+F5uMMSHzng0N9Xjvcw96pYWKk8wpICtaKLZqVA9Dbli/y3Hak//1e\n1N3Eh1Eo7eEvTJLVporyiM1G6WjtfAb2cbYXrd8BxLAyS3KuhdiMsPs2VPJnuVYC\nzQencUxi+xJGQkqvqjyADT1VVdhwudCFYUmoXQIDAQABAoIBADNEezYOrlxZraLg\nuT6BOzwpfnUfJBn9qei3mMGYUT+FyU7FN4xQ0O0iHDX4HjZMzUCrouNQuZ3iK6aW\n3AlWInt6gI4Zz9Vfw29roF6azyniLmrJznIUb7BfqyoqZsI9k8tz/uPhwHcEtsxB\nitOwsBiu3jQc47XgJ8k37tunFSYmcWoTkBox9FJoA4w7cHL5rSbHpYMv4pd5oV/9\n/Uwm/Im4G9Pij1gY6jLGyXMybLuAlB3ZcMEV4X+O7jgrmd8jvIZp+A66viOyqK8U\nTogeBXlmMDeuyV5yAGjxWJI3OqJey6qEQfh7zq6XGWLwhC+8pyjgd8xrERy3p/JL\n/Jb+pUECgYEA5xCGli1pUG8guvp6iwXKmsgNBaNsOtVqHgb0um1InHAsfRslpM38\nDeHrC5gD4DOoSioVgbHF7ppqHpEh41MbzJWfdSPhAVoBIUZiD/jFTnAiird48+3F\nnKFIv6NULyFy/z1Y0cjrcEkjJSCrlqKPKPZzdBfrBrNDS8w2YMTVitECgYEAwvzK\ntnbVqbP4wvvSyMamfPKAKFEGV+5dvelf61uecUGlwrrTYc3y5W6PThUM5ZdXwNXp\nYmgaY5coGy0o1CM6MBJ7bx4Aw1ygZNbrer+guUPNQkKjl2NiLhSLRm2ga1XAysxd\nyWQm2NDlMFzZgnGvxHj5+AGsZfGRQpBMzHwDT80CgYEAiIszfTuIqIeDB/tMvyrE\n94KQb2yLYJkNBIGHzUMXTZrcL3IDZMh00p9WjptebvcX0/vaibHMDZwiab3KENPj\n8ZnZiReSt4HAeTFmcZnIvvl08BRL3Zn81PpaSyTxcoiJtFtESXQ57TjLE/2iaHnX\nr5Uz1L7tnCAC/J/I4pZuuoECgYEAiQAS8hcW0rDYBS/ojxc8XSgJscoUOe4KQWha\n88Qg1BS7AdJAuUR5+Igw+jzCHgKzLpNd8r2QZQ8Mp+OX/01tEd+6iH09LgbDz3ZO\nZ6WCqQkhi//Eb5btodDfdrGJ+EB9QEBNWTYcMVS847kpPoTgaZxSjdWnKs2LMYiv\n3TD5JrUCgYEAxpZQkT7VA1loPCjZosplW+dvNQFxBaO4nKKVgOlWrkitdi6MtRPC\n5I9+hPaBBr6puNq7MyRBrlgafYSh5GiayUg4rWZZuQbTtKsWGxvyqk/Eh9FQ2uK0\nkGurKO91ZZetoaQIYvml3lAaufFZmZhLWK07dFQyOadvn6hVouQF8KU=\n-----END RSA PRIVATE KEY-----",
				matches: []string{
					"-----BEGIN RSA PRIVATE KEY-----\nMIIEpQIBAAKCAQEAr/6xOgVzKS5UWluWl19TCWILfJvVlnAFcwh7KyA1GWy/mhF9\nfiyrj1j9Yt9S1fmVk1CZLPTsQYrnAGVNrwJYHy1B44XyOyFcNLaiT6sB+wC91lps\nUfGRfXa1L7fsUtJCxB+7PBHP+kbMqw498QBwjPJEZsIIUvnXLFdgh3YpWDHutyXo\npN0U4WJin5+F5uMMSHzng0N9Xjvcw96pYWKk8wpICtaKLZqVA9Dbli/y3Hak//1e\n1N3Eh1Eo7eEvTJLVporyiM1G6WjtfAb2cbYXrd8BxLAyS3KuhdiMsPs2VPJnuVYC\nzQencUxi+xJGQkqvqjyADT1VVdhwudCFYUmoXQIDAQABAoIBADNEezYOrlxZraLg\nuT6BOzwpfnUfJBn9qei3mMGYUT+FyU7FN4xQ0O0iHDX4HjZMzUCrouNQuZ3iK6aW\n3AlWInt6gI4Zz9Vfw29roF6azyniLmrJznIUb7BfqyoqZsI9k8tz/uPhwHcEtsxB\nitOwsBiu3jQc47XgJ8k37tunFSYmcWoTkBox9FJoA4w7cHL5rSbHpYMv4pd5oV/9\n/Uwm/Im4G9Pij1gY6jLGyXMybLuAlB3ZcMEV4X+O7jgrmd8jvIZp+A66viOyqK8U\nTogeBXlmMDeuyV5yAGjxWJI3OqJey6qEQfh7zq6XGWLwhC+8pyjgd8xrERy3p/JL\n/Jb+pUECgYEA5xCGli1pUG8guvp6iwXKmsgNBaNsOtVqHgb0um1InHAsfRslpM38\nDeHrC5gD4DOoSioVgbHF7ppqHpEh41MbzJWfdSPhAVoBIUZiD/jFTnAiird48+3F\nnKFIv6NULyFy/z1Y0cjrcEkjJSCrlqKPKPZzdBfrBrNDS8w2YMTVitECgYEAwvzK\ntnbVqbP4wvvSyMamfPKAKFEGV+5dvelf61uecUGlwrrTYc3y5W6PThUM5ZdXwNXp\nYmgaY5coGy0o1CM6MBJ7bx4Aw1ygZNbrer+guUPNQkKjl2NiLhSLRm2ga1XAysxd\nyWQm2NDlMFzZgnGvxHj5+AGsZfGRQpBMzHwDT80CgYEAiIszfTuIqIeDB/tMvyrE\n94KQb2yLYJkNBIGHzUMXTZrcL3IDZMh00p9WjptebvcX0/vaibHMDZwiab3KENPj\n8ZnZiReSt4HAeTFmcZnIvvl08BRL3Zn81PpaSyTxcoiJtFtESXQ57TjLE/2iaHnX\nr5Uz1L7tnCAC/J/I4pZuuoECgYEAiQAS8hcW0rDYBS/ojxc8XSgJscoUOe4KQWha\n88Qg1BS7AdJAuUR5+Igw+jzCHgKzLpNd8r2QZQ8Mp+OX/01tEd+6iH09LgbDz3ZO\nZ6WCqQkhi//Eb5btodDfdrGJ+EB9QEBNWTYcMVS847kpPoTgaZxSjdWnKs2LMYiv\n3TD5JrUCgYEAxpZQkT7VA1loPCjZosplW+dvNQFxBaO4nKKVgOlWrkitdi6MtRPC\n5I9+hPaBBr6puNq7MyRBrlgafYSh5GiayUg4rWZZuQbTtKsWGxvyqk/Eh9FQ2uK0\nkGurKO91ZZetoaQIYvml3lAaufFZmZhLWK07dFQyOadvn6hVouQF8KU=\n-----END RSA PRIVATE KEY-----",
				},
			},
			{
				// Ensure that we capture each of two private keys in a single 'file' (i.e. ensure we don't greedily match the beginning of the first and the end of the second).
				input: "-----BEGIN RSA PRIVATE KEY-----\nMIIEpQIBAAKCAQEAr/6xOgVzKS5UWluWl19TCWILfJvVlnAFcwh7KyA1GWy/mhF9\nfiyrj1j9Yt9S1fmVk1CZLPTsQYrnAGVNrwJYHy1B44XyOyFcNLaiT6sB+wC91lps\nUfGRfXa1L7fsUtJCxB+7PBHP+kbMqw498QBwjPJEZsIIUvnXLFdgh3YpWDHutyXo\npN0U4WJin5+F5uMMSHzng0N9Xjvcw96pYWKk8wpICtaKLZqVA9Dbli/y3Hak//1e\n1N3Eh1Eo7eEvTJLVporyiM1G6WjtfAb2cbYXrd8BxLAyS3KuhdiMsPs2VPJnuVYC\nzQencUxi+xJGQkqvqjyADT1VVdhwudCFYUmoXQIDAQABAoIBADNEezYOrlxZraLg\nuT6BOzwpfnUfJBn9qei3mMGYUT+FyU7FN4xQ0O0iHDX4HjZMzUCrouNQuZ3iK6aW\n3AlWInt6gI4Zz9Vfw29roF6azyniLmrJznIUb7BfqyoqZsI9k8tz/uPhwHcEtsxB\nitOwsBiu3jQc47XgJ8k37tunFSYmcWoTkBox9FJoA4w7cHL5rSbHpYMv4pd5oV/9\n/Uwm/Im4G9Pij1gY6jLGyXMybLuAlB3ZcMEV4X+O7jgrmd8jvIZp+A66viOyqK8U\nTogeBXlmMDeuyV5yAGjxWJI3OqJey6qEQfh7zq6XGWLwhC+8pyjgd8xrERy3p/JL\n/Jb+pUECgYEA5xCGli1pUG8guvp6iwXKmsgNBaNsOtVqHgb0um1InHAsfRslpM38\nDeHrC5gD4DOoSioVgbHF7ppqHpEh41MbzJWfdSPhAVoBIUZiD/jFTnAiird48+3F\nnKFIv6NULyFy/z1Y0cjrcEkjJSCrlqKPKPZzdBfrBrNDS8w2YMTVitECgYEAwvzK\ntnbVqbP4wvvSyMamfPKAKFEGV+5dvelf61uecUGlwrrTYc3y5W6PThUM5ZdXwNXp\nYmgaY5coGy0o1CM6MBJ7bx4Aw1ygZNbrer+guUPNQkKjl2NiLhSLRm2ga1XAysxd\nyWQm2NDlMFzZgnGvxHj5+AGsZfGRQpBMzHwDT80CgYEAiIszfTuIqIeDB/tMvyrE\n94KQb2yLYJkNBIGHzUMXTZrcL3IDZMh00p9WjptebvcX0/vaibHMDZwiab3KENPj\n8ZnZiReSt4HAeTFmcZnIvvl08BRL3Zn81PpaSyTxcoiJtFtESXQ57TjLE/2iaHnX\nr5Uz1L7tnCAC/J/I4pZuuoECgYEAiQAS8hcW0rDYBS/ojxc8XSgJscoUOe4KQWha\n88Qg1BS7AdJAuUR5+Igw+jzCHgKzLpNd8r2QZQ8Mp+OX/01tEd+6iH09LgbDz3ZO\nZ6WCqQkhi//Eb5btodDfdrGJ+EB9QEBNWTYcMVS847kpPoTgaZxSjdWnKs2LMYiv\n3TD5JrUCgYEAxpZQkT7VA1loPCjZosplW+dvNQFxBaO4nKKVgOlWrkitdi6MtRPC\n5I9+hPaBBr6puNq7MyRBrlgafYSh5GiayUg4rWZZuQbTtKsWGxvyqk/Eh9FQ2uK0\nkGurKO91ZZetoaQIYvml3lAaufFZmZhLWK07dFQyOadvn6hVouQF8KU=\n-----END RSA PRIVATE KEY-----\n\n-----BEGIN RSA PRIVATE KEY-----\nNJJEpQIBAAKCAQEAr/6xOgVzKS5UWluWl19TCWILfJvVlnAFcwh7KyA1GWy/mhF9\nfiyrj1j9Yt9S1fmVk1CZLPTsQYrnAGVNrwJYHy1B44XyOyFcNLaiT6sB+wC91lps\nUfGRfXa1L7fsUtJCxB+7PBHP+kbMqw498QBwjPJEZsIIUvnXLFdgh3YpWDHutyXo\npN0U4WJin5+F5uMMSHzng0N9Xjvcw96pYWKk8wpICtaKLZqVA9Dbli/y3Hak//1e\n1N3Eh1Eo7eEvTJLVporyiM1G6WjtfAb2cbYXrd8BxLAyS3KuhdiMsPs2VPJnuVYC\nzQencUxi+xJGQkqvqjyADT1VVdhwudCFYUmoXQIDAQABAoIBADNEezYOrlxZraLg\nuT6BOzwpfnUfJBn9qei3mMGYUT+FyU7FN4xQ0O0iHDX4HjZMzUCrouNQuZ3iK6aW\n3AlWInt6gI4Zz9Vfw29roF6azyniLmrJznIUb7BfqyoqZsI9k8tz/uPhwHcEtsxB\nitOwsBiu3jQc47XgJ8k37tunFSYmcWoTkBox9FJoA4w7cHL5rSbHpYMv4pd5oV/9\n/Uwm/Im4G9Pij1gY6jLGyXMybLuAlB3ZcMEV4X+O7jgrmd8jvIZp+A66viOyqK8U\nTogeBXlmMDeuyV5yAGjxWJI3OqJey6qEQfh7zq6XGWLwhC+8pyjgd8xrERy3p/JL\n/Jb+pUECgYEA5xCGli1pUG8guvp6iwXKmsgNBaNsOtVqHgb0um1InHAsfRslpM38\nDeHrC5gD4DOoSioVgbHF7ppqHpEh41MbzJWfdSPhAVoBIUZiD/jFTnAiird48+3F\nnKFIv6NULyFy/z1Y0cjrcEkjJSCrlqKPKPZzdBfrBrNDS8w2YMTVitECgYEAwvzK\ntnbVqbP4wvvSyMamfPKAKFEGV+5dvelf61uecUGlwrrTYc3y5W6PThUM5ZdXwNXp\nYmgaY5coGy0o1CM6MBJ7bx4Aw1ygZNbrer+guUPNQkKjl2NiLhSLRm2ga1XAysxd\nyWQm2NDlMFzZgnGvxHj5+AGsZfGRQpBMzHwDT80CgYEAiIszfTuIqIeDB/tMvyrE\n94KQb2yLYJkNBIGHzUMXTZrcL3IDZMh00p9WjptebvcX0/vaibHMDZwiab3KENPj\n8ZnZiReSt4HAeTFmcZnIvvl08BRL3Zn81PpaSyTxcoiJtFtESXQ57TjLE/2iaHnX\nr5Uz1L7tnCAC/J/I4pZuuoECgYEAiQAS8hcW0rDYBS/ojxc8XSgJscoUOe4KQWha\n88Qg1BS7AdJAuUR5+Igw+jzCHgKzLpNd8r2QZQ8Mp+OX/01tEd+6iH09LgbDz3ZO\nZ6WCqQkhi//Eb5btodDfdrGJ+EB9QEBNWTYcMVS847kpPoTgaZxSjdWnKs2LMYiv\n3TD5JrUCgYEAxpZQkT7VA1loPCjZosplW+dvNQFxBaO4nKKVgOlWrkitdi6MtRPC\n5I9+hPaBBr6puNq7MyRBrlgafYSh5GiayUg4rWZZuQbTtKsWGxvyqk/Eh9FQ2uK0\nkGurKO91ZZetoaQIYvml3lAaufFZmZhLWK07dFQyOadvn6hVouQF9LV=\n-----END RSA PRIVATE KEY-----",
				matches: []string{
					"-----BEGIN RSA PRIVATE KEY-----\nMIIEpQIBAAKCAQEAr/6xOgVzKS5UWluWl19TCWILfJvVlnAFcwh7KyA1GWy/mhF9\nfiyrj1j9Yt9S1fmVk1CZLPTsQYrnAGVNrwJYHy1B44XyOyFcNLaiT6sB+wC91lps\nUfGRfXa1L7fsUtJCxB+7PBHP+kbMqw498QBwjPJEZsIIUvnXLFdgh3YpWDHutyXo\npN0U4WJin5+F5uMMSHzng0N9Xjvcw96pYWKk8wpICtaKLZqVA9Dbli/y3Hak//1e\n1N3Eh1Eo7eEvTJLVporyiM1G6WjtfAb2cbYXrd8BxLAyS3KuhdiMsPs2VPJnuVYC\nzQencUxi+xJGQkqvqjyADT1VVdhwudCFYUmoXQIDAQABAoIBADNEezYOrlxZraLg\nuT6BOzwpfnUfJBn9qei3mMGYUT+FyU7FN4xQ0O0iHDX4HjZMzUCrouNQuZ3iK6aW\n3AlWInt6gI4Zz9Vfw29roF6azyniLmrJznIUb7BfqyoqZsI9k8tz/uPhwHcEtsxB\nitOwsBiu3jQc47XgJ8k37tunFSYmcWoTkBox9FJoA4w7cHL5rSbHpYMv4pd5oV/9\n/Uwm/Im4G9Pij1gY6jLGyXMybLuAlB3ZcMEV4X+O7jgrmd8jvIZp+A66viOyqK8U\nTogeBXlmMDeuyV5yAGjxWJI3OqJey6qEQfh7zq6XGWLwhC+8pyjgd8xrERy3p/JL\n/Jb+pUECgYEA5xCGli1pUG8guvp6iwXKmsgNBaNsOtVqHgb0um1InHAsfRslpM38\nDeHrC5gD4DOoSioVgbHF7ppqHpEh41MbzJWfdSPhAVoBIUZiD/jFTnAiird48+3F\nnKFIv6NULyFy/z1Y0cjrcEkjJSCrlqKPKPZzdBfrBrNDS8w2YMTVitECgYEAwvzK\ntnbVqbP4wvvSyMamfPKAKFEGV+5dvelf61uecUGlwrrTYc3y5W6PThUM5ZdXwNXp\nYmgaY5coGy0o1CM6MBJ7bx4Aw1ygZNbrer+guUPNQkKjl2NiLhSLRm2ga1XAysxd\nyWQm2NDlMFzZgnGvxHj5+AGsZfGRQpBMzHwDT80CgYEAiIszfTuIqIeDB/tMvyrE\n94KQb2yLYJkNBIGHzUMXTZrcL3IDZMh00p9WjptebvcX0/vaibHMDZwiab3KENPj\n8ZnZiReSt4HAeTFmcZnIvvl08BRL3Zn81PpaSyTxcoiJtFtESXQ57TjLE/2iaHnX\nr5Uz1L7tnCAC/J/I4pZuuoECgYEAiQAS8hcW0rDYBS/ojxc8XSgJscoUOe4KQWha\n88Qg1BS7AdJAuUR5+Igw+jzCHgKzLpNd8r2QZQ8Mp+OX/01tEd+6iH09LgbDz3ZO\nZ6WCqQkhi//Eb5btodDfdrGJ+EB9QEBNWTYcMVS847kpPoTgaZxSjdWnKs2LMYiv\n3TD5JrUCgYEAxpZQkT7VA1loPCjZosplW+dvNQFxBaO4nKKVgOlWrkitdi6MtRPC\n5I9+hPaBBr6puNq7MyRBrlgafYSh5GiayUg4rWZZuQbTtKsWGxvyqk/Eh9FQ2uK0\nkGurKO91ZZetoaQIYvml3lAaufFZmZhLWK07dFQyOadvn6hVouQF8KU=\n-----END RSA PRIVATE KEY-----",
					"-----BEGIN RSA PRIVATE KEY-----\nNJJEpQIBAAKCAQEAr/6xOgVzKS5UWluWl19TCWILfJvVlnAFcwh7KyA1GWy/mhF9\nfiyrj1j9Yt9S1fmVk1CZLPTsQYrnAGVNrwJYHy1B44XyOyFcNLaiT6sB+wC91lps\nUfGRfXa1L7fsUtJCxB+7PBHP+kbMqw498QBwjPJEZsIIUvnXLFdgh3YpWDHutyXo\npN0U4WJin5+F5uMMSHzng0N9Xjvcw96pYWKk8wpICtaKLZqVA9Dbli/y3Hak//1e\n1N3Eh1Eo7eEvTJLVporyiM1G6WjtfAb2cbYXrd8BxLAyS3KuhdiMsPs2VPJnuVYC\nzQencUxi+xJGQkqvqjyADT1VVdhwudCFYUmoXQIDAQABAoIBADNEezYOrlxZraLg\nuT6BOzwpfnUfJBn9qei3mMGYUT+FyU7FN4xQ0O0iHDX4HjZMzUCrouNQuZ3iK6aW\n3AlWInt6gI4Zz9Vfw29roF6azyniLmrJznIUb7BfqyoqZsI9k8tz/uPhwHcEtsxB\nitOwsBiu3jQc47XgJ8k37tunFSYmcWoTkBox9FJoA4w7cHL5rSbHpYMv4pd5oV/9\n/Uwm/Im4G9Pij1gY6jLGyXMybLuAlB3ZcMEV4X+O7jgrmd8jvIZp+A66viOyqK8U\nTogeBXlmMDeuyV5yAGjxWJI3OqJey6qEQfh7zq6XGWLwhC+8pyjgd8xrERy3p/JL\n/Jb+pUECgYEA5xCGli1pUG8guvp6iwXKmsgNBaNsOtVqHgb0um1InHAsfRslpM38\nDeHrC5gD4DOoSioVgbHF7ppqHpEh41MbzJWfdSPhAVoBIUZiD/jFTnAiird48+3F\nnKFIv6NULyFy/z1Y0cjrcEkjJSCrlqKPKPZzdBfrBrNDS8w2YMTVitECgYEAwvzK\ntnbVqbP4wvvSyMamfPKAKFEGV+5dvelf61uecUGlwrrTYc3y5W6PThUM5ZdXwNXp\nYmgaY5coGy0o1CM6MBJ7bx4Aw1ygZNbrer+guUPNQkKjl2NiLhSLRm2ga1XAysxd\nyWQm2NDlMFzZgnGvxHj5+AGsZfGRQpBMzHwDT80CgYEAiIszfTuIqIeDB/tMvyrE\n94KQb2yLYJkNBIGHzUMXTZrcL3IDZMh00p9WjptebvcX0/vaibHMDZwiab3KENPj\n8ZnZiReSt4HAeTFmcZnIvvl08BRL3Zn81PpaSyTxcoiJtFtESXQ57TjLE/2iaHnX\nr5Uz1L7tnCAC/J/I4pZuuoECgYEAiQAS8hcW0rDYBS/ojxc8XSgJscoUOe4KQWha\n88Qg1BS7AdJAuUR5+Igw+jzCHgKzLpNd8r2QZQ8Mp+OX/01tEd+6iH09LgbDz3ZO\nZ6WCqQkhi//Eb5btodDfdrGJ+EB9QEBNWTYcMVS847kpPoTgaZxSjdWnKs2LMYiv\n3TD5JrUCgYEAxpZQkT7VA1loPCjZosplW+dvNQFxBaO4nKKVgOlWrkitdi6MtRPC\n5I9+hPaBBr6puNq7MyRBrlgafYSh5GiayUg4rWZZuQbTtKsWGxvyqk/Eh9FQ2uK0\nkGurKO91ZZetoaQIYvml3lAaufFZmZhLWK07dFQyOadvn6hVouQF9LV=\n-----END RSA PRIVATE KEY-----",
				},
			},
		},
		"GITLAB_ACCESS_TOKEN": {
			{input: "glpat-eJz_zGvD8kL_sreBWkWz"},
			{input: "glpat-oirzs4y-zGKTbzxrzszE"},
		},
		"GOCARDLESS_LIVE_ACCESS_TOKEN": {
			{input: "live_sXkDNABRzRcSmrHrmMLQ-GdZVCbjmTj2ZssAjPSJW"},
			{input: "live-yYlCxczgGSzyyolhaU4ZAfEH8pXR6ZW_b5RiU24TjaY"},
		},
		"GOCARDLESS_SANDBOX_ACCESS_TOKEN": {
			{input: "sandbox_sXkDNABRzRcSmrHrmMLQ-GdZVCbjmTj2ZssAjPSJW"},
			{input: "sandbox-yYlCxczgGSzyyolhaU4ZAfEH8pXR6ZW_b5RiU24TjaY"},
		},
		"GOOGLE_GCP_PRIVATE_KEY_ID": {
			{
				input:   "\"private_key_id\" : \"f3cadbc97629b0aaac9ecabaa0f661456042de6c\"",
				matches: []string{"f3cadbc97629b0aaac9ecabaa0f661456042de6c"},
			},
			{
				input:   "\"private_key_id\":\"f3cadbc97629b0aaac9ecabaa0f661456042de6c\"",
				matches: []string{"f3cadbc97629b0aaac9ecabaa0f661456042de6c"},
			},
			{
				input:          "\"f3cadbc97629b0aaac9ecabaa0f661456042de6c\"",
				shouldNotMatch: true,
			},
		},
		"GOOGLE_API_KEY": {
			{input: "AIzaSyAX9VY1Gqb0xghcj3IJ64h71dqLVjpsgTQ"},
			{input: "AIzaSyCI6K2Rrd_z8IDGr7Z2ULT-fzC0ro6PqDQ"},
		},
		"GOOGLE_CLOUD_STORAGE_ACCESS_KEY_SECRET": {
			{input: "qFJstF8hiXsrnja/W0YgtC75k7UkF/Bu/S9eePzT"},
			{input: "UwH7dCm5DnfK2bsTKP1JPaqn1rZ1lv+jOpWBGptj"},
		},
		"GOOGLE_CLOUD_STORAGE_SERVICE_ACCOUNT_ACCESS_KEY_ID": {
			{input: "GOOG1E6I22EAVBB7CAHG6S5D2SDWX7TRKLHZLWGSUI5QAYN2EKGPBXE3HRLHA"},
			{input: "GOOG1EGKNLOG7M6YLGQEJT2XFPXC4DXXMFP4KETIWBWI2WPNGNKP2OGDMRQZY"},
		},
		"GOOGLE_CLOUD_STORAGE_USER_ACCESS_KEY_ID": {
			{input: "GOOGAX5KHQLEQ3VLAWZPG4W2"},
			{input: "GOOG6UCNASJRP46GNDLER3G2"},
		},
		"GOOGLE_OAUTH_ACCESS_TOKEN": {
			{input: "ya29.GlvRBKN_2tAdXmimVXYl6iQDOXJ_Esm72saE7wuTo84FQO9duPfy2mNpfQBeMDemJgxYYwKse1bjStCWdwKd-Wjhhk3dUtNV8jbilwSHYIpUNJtuSACMXuv11e5T"},
			{input: "ya29.a0ARrdaM_BiTSuPoLgYw1hj6znCuiTGWLCZ5OVXOzhsjk76JdhnAW60xkTAAMaImVSlJWTXlK4O2K-K-XLo8M6Nn2NGyHWiNVM05-_1INL6MFRH2lQYfT3VWIYJ5fpttEbW9WwUdwQl8twmIuiU3hsrJwc7JZXdg"},
			{input: "ya29.a0ARrdaM8UmSCE6zb42ciAEA4ixToqRSYD8YQS7jZ0clUtktlaAQr7X1q-Cv0H8ztNHQRecJTSrIkW3lhYbosq5tn0yE6UsrTHyHVA_iQItUt2X_Nyw44poc37rMyZAKi5uZdkEvE57QeSbWF3RyNEecc6C-_P"},
		},
		"GOOGLE_OAUTH_CLIENT_ID": {
			{input: "783824127513-3cv5i6ae0120boge1i1sgo8hc41356lu.apps.googleusercontent.com"},
		},
		"GOOGLE_OAUTH_CLIENT_SECRET": {
			{input: "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"},
		},
		"GOOGLE_OAUTH_REFRESH_TOKEN": {
			{input: "1//0408h33-m04hoCgYIARAAGAQSNwF-L9IrSeP73Nl2hR6CMcfjz3Lo3LabjWZtIs5wYA2Ah5nCmzTxBbTRHf5H5WzqxcNu98kp1ec"},
		},
		"GOPKG_LOCK_DIGEST": {
			{
				input:   "   digest = \"1:08636edd4ac1b095a9689b7a07763aa70e035068e0ff0e9dbfe2b6299b98e498\"",
				matches: []string{"digest = "},
			},
		},
		"GOPKG_LOCK_REVISION": {
			{
				input:   "   revision = \"0ebda48a7f143b1cce9eb37a8c1106ac762a3430\"",
				matches: []string{"revision = "},
			},
		},
		"GRAFANA_PROJECT_API_KEY": {
			{input: "eyJrIjoiNTViZThiNjA4ZThiM2Q4MWUyZjc0MmZhNjhmNjcxZmNkMjA2ZmU2YiIsIm4iOiJhIiwiaWQiOjQ3Mzk3NX0=="},
			{input: "eyJrIjoiZWNYeU1hTXNvTm41Y1c0ZjFqUW1RUmRWVDNzWkFJeHIiLCJuIjoiNTU1NTUiLCJpZCI6MX0="},
			{input: "eyJrIjoiRTJ2UExXUkdkU0o2enN2Slg4andXNHdDQW9ZRGM4ZzgiLCJuIjoiNDQ0NDQiLCJpZCI6MX0="},
			{input: "eyJrIjoicmNRUlp2ajB3WnZXdXBOUUk3bEhRckRYdDlwMmp6ZkciLCJuIjoiMzMzIiwiaWQiOjF9"},
			{input: "eyJrIjoiVXIwNm1pbWtOd241UGF3c3BCVjM3NzZzQTFBd1kwQWEiLCJuIjoiMiIsImlkIjoxfQ=="},
			{input: "eyJrIjoiUnFXWXR0empEamNQblcxNGswc0hMSkxBVjNzcnNNUWciLCJuIjoiMSIsImlkIjoxfQ=="},
		},
		"GRAFANA_CLOUD_API_KEY": {
			{input: "eyJrIjoiNzE0Mjg3ZDIyNTg4ZDI4ZDdkMmJjOTZlMmNjYmM3ZDgzMzY5ZGZjNCIsIm4iOiIyIiwiaWQiOjIyNDIwMn0="},
			{input: "eyJrIjoiNzAzNjM2NmZiZTRhMDNmMzE3Yzc4ZTg5ZWM0OGYxMmUyZThiMGM0ZSIsIm4iOiIzIiwiaWQiOjIyNDIwMn0="},
			{input: "eyJrIjoiODVjMzljYmY3MDc3ZTJhZTg1ZDBmZmJkNzA1YTQ1NGJlMTc3ZDZiYyIsIm4iOiI0IiwiaWQiOjIyNDIwMn0="},
			{input: "eyJrIjoiYWJhYzRlMWMwMGQ1NWIwNDdlMjg3ODE5ZjBiNThhN2Y0MTcyYmNmYSIsIm4iOiI0IiwiaWQiOjIyNDIwMn0="},
			{input: "eyJrIjoiY2QyMTU5MzExY2Y2ZGQzNmRmMjdmYTdmNTY2ODMyMzM5ZGY0ZTc2YSIsIm4iOiIxIiwiaWQiOjIyNDIwMn0="},
		},
		"GRAFANA_CLOUD_API_TOKEN": {
			{input: "glc_eyJvIjoiMjI0MjAyIiwibiI6InRlc3RpbmctMSIsImsiOiI/OCQxMm4hLnwzLUEtSCMxMVI/YDU5NTQiLCJtIjp7InIiOiJ1cyJ9fQ=="},
			{input: "glc_eyJvIjoiMjI0MjAyIiwibiI6InRlc3RpbmctMiIsImsiOiIzKTApezBcdTAwM2NKayxcdTAwM2U2OCF0fTckMjksMHY0IiwibSI6eyJyIjoidXMifX0="},
			{input: "glc_eyJvIjoiMjI0MjAyIiwibiI6InRlc3RpbmctMyIsImsiOiI9cTFYMjpgXzI0fjYrMW1+NikzXHUwMDI2NjVHLCIsIm0iOnsiciI6InVzIn19"},
			{input: "glc_eyJvIjoiMjI0MjAyIiwibiI6InRlc3RpbmctNCIsImsiOiJgKTYyLzg1MDBAXFxiTX5cdTAwM2M0XTcxMk0lK1MiLCJtIjp7InIiOiJ1cyJ9fQ=="},
			{input: "glc_eyJvIjoiMjI0MjAyIiwibiI6InRlc3RpbmctNSIsImsiOiJJYDk6OTVcdTAwM2NASjYhXS4zMThGWFx1MDAzYzUwMC1gIiwibSI6eyJyIjoidXMifX0="},
		},
		"GRAFANA_PROJECT_SERVICE_ACCOUNT_TOKEN": {
			{input: "glsa_uQ6NwgvxK79oco05WmlpiKGZAcvw4Y8S_432c2511"},
			{input: "glsa_x8c5YhJ04LukLjIP7Tf7TG0IJrZvp7yW_5cf24476"},
			{input: "glsa_1fkniuMYHUdA0nknt0pcCOr8Rc0kue34_38c4cdc3"},
			{input: "glsa_FrTKmdnFYaR61AYmKGRt9y3c7pt54H7i_53168e0e"},
			{input: "glsa_6xmAxd67P3ApqrMKHGvfDKi7j3ACHPWd_87e7e6ee"},
		},
		"GUID_PRESENCE": {
			{input: "6A65B38E-419B-4155-B15C-254F750D28AE"},
			{input: "6a65b38e-419b-4155-b15c-254f750d28af"},
		},
		"HEROKU_CLEARDB_MYSQL_CONNECTION_URL": {
			{input: "mysql://b11f6da952c2c1:950a9fba@us-cdbr-east-04.cleardb.com/heroku_d2bc9ee81b59706"},
			{input: "mysql://bab29a36380b92:c311e4ef@us-cdbr-iron-east-05.cleardb.net/heroku_b45cf858d7d7a07"},
		},
		"HEROKU_POSTGRES_CONNECTION_URL": {
			{input: "postgres://ywrhatcgbxoejq:26a84cd5dad20e0ae6ecd7daef2604d65127edd9d4ca2d9564607fde0aba9654@ec2-54-211-160-34.compute-1.amazonaws.com:5432/d137o92e0f26u0"},
			{input: "POSTGRESQL://ywrhatcgbxoejq:26a84cd5dad20e0ae6ecd7daef2604d65127edd9d4ca2d9564607fde0aba9654@ec2-54-211-160-34.eu-west-1.compute.amazonaws.com/d137o92e0f26u0"},
			{input: "postgres://ywrhatcgbxoejq:26a84cd5dad20e0ae6ecd7daef2604d65127edd9d4ca2d9564607fde0aba9654@ec2-54-211-160-34.compute-1.amazonaws.com:5432/d137o92e0f26u"},
		},
		"HELM_INDEX_VERSION": {
			{
				input:   "        version: 0.3.0-adeec2927c67b651bf553a1c33d425488bd07a3b",
				matches: []string{"version: 0.3.0"},
			},
		},
		"HIGHNOTE_RK_LIVE_KEY": {
			{input: "rk_live_9ty72Lq6xxHZ3w6yvezLze8HsAtVS8VaSjsgTxGVZo23Xe34oU4qrV2bEARfPbhYBaDeJAYAaiLsaMAs9y"},
		},
		"HIGHNOTE_RK_TEST_KEY": {
			{input: "rk_test_9ty72Lq6xxHZ3w6yvezLze8HsAtVS8VaSjsgTxGVZo23Xe34oU4qrV2bEARfPbhYBaDeJAYAaiLsaMAs9y"},
		},
		"HIGHNOTE_SK_LIVE_KEY": {
			{input: "sk_live_9ty72Lq6xxHZ3w6yvezLze8HsAtVS8VaSjsgTxGVZo23Xe34oU4qrV2bEARfPbhYBaDeJAYAaiLsaMAs9y"},
		},
		"HIGHNOTE_SK_TEST_KEY": {
			{input: "sk_test_9ty72Lq6xxHZ3w6yvezLze8HsAtVS8VaSjsgTxGVZo23Xe34oU4qrV2bEARfPbhYBaDeJAYAaiLsaMAs9y"},
		},
		"HTTP_BASIC_AUTHENTICATION_HEADER": {
			{
				input:   "Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ==",
				matches: []string{"QWxhZGRpbjpvcGVuIHNlc2FtZQ=="},
			},
			{
				input:   "BASIC QWxhZGRpbjpvcGVuIHNlc2FtZQ==",
				matches: []string{"QWxhZGRpbjpvcGVuIHNlc2FtZQ=="},
			},
			{
				input:   "basic QWxhZGRpbjpvcGVuIHNlc2FtZQ==",
				matches: []string{"QWxhZGRpbjpvcGVuIHNlc2FtZQ=="},
			},
		},
		"HUBSPOT_SMTP": {
			{input: "smtp.hubspot.net"},
			{input: "Smtp.Hubspot.Net"},
			{input: "SMTP.HUBSPOT.NET"},
		},
		"HUBSPOT_HAPIKEY_NAME_PRESENCE": {
			{input: "hapikey"},
			{input: "HAPIKEY"},
			{input: "Hapikey"},
		},
		"HUBSPOT_HAPIKEY": {
			{input: "e4c67e1d-2c16-436e-a015-225482a5836c"},
			{input: "a4c67e1e-2c46-433e-a014-235482a5837e"},
			{input: "ffc6fe6d-2c16-436e-a015-225482a5836f"},
		},
		"HUBSPOT_API_KEY_PRECISE": {
			{
				input:   "hapikey: 'e4c67e1d-2c16-436e-a015-225482a5836c'",
				matches: []string{"e4c67e1d-2c16-436e-a015-225482a5836c"},
			},
			{
				input:   "HAPIKEY = \"a4c67e1e-2c46-433e-a014-235482a5837e\"",
				matches: []string{"a4c67e1e-2c46-433e-a014-235482a5837e"},
			},
			{
				input:   "Hapikey = ffc6fe6d-2c16-436e-a015-225482a5836f",
				matches: []string{"ffc6fe6d-2c16-436e-a015-225482a5836f"},
			},
		},
		"HUBSPOT_API_KEY_WITH_PREFIX": {
			{input: "pat-eu1-e4c67e1d-2c16-436e-a015-225482a5836c"},
			{input: "pat-na1-ffc6fe6d-2c16-436e-a015-225482a5836f"},
		},
		"HUBSPOT_API_PERSONAL_ACCESS_KEY": {
			{input: `CiRldTEtN2FjMi04ZjQ3LTQ0NjAtYjk2MS1iYzE1ZTdjNGNmYTYQgOSVDBjM7MINKhkABeaRgnT2uVni73e5gFnF3Cz9PMMRmA51SgNldTE`},
			{input: `CiRldTEtN2FjMi04ZjQ3LTQ0NjAtYjk2MS1iYzE1ZTdjNGNmYTYQgOSVDBjM7MINKhkABeaRgnT2uAF1Vni73e5gFnF3Cz9PMMRmA51SgNldTE`}, // max length
			{input: `CiRldTEtN2FjMi04ZjQ3LTQ0NjAtYjk2MS1iYzE1ZTdjNGNmYTYQgOSVDBjM7MINKhkABeaRgnT2uAF1aVni7PaMMRA51SgNldTE`},           // min length
			{ // too long
				input:          "CiRldTEtN2FjMi04ZjQ3LTQ0NjAtYjk2MS1iYzE1ZTdjNGNmYTYQgOSVDBjM7MINKhkABeaRgnT2uAF1aVni73e5gFnF3Cz9PMMRmA51SgNldTE",
				shouldNotMatch: true,
			},
			{ // too short
				input:          "CiRldTEtN2FjMi04ZjQ3LTQ0NjAtYjk2MS1iYzE1ZTdjNGNmYTYQgOSVDBjM7MINKhkABeaRgnT2uAF1aVni7PMMRA51SgNldTE",
				shouldNotMatch: true,
			},
		},
		"IBM_CLOUD_IAM_KEY": {
			{
				input:   "Text IBM_CLOUD_IAM_KEY = b2L1liMCcap6dKPMj_jKlrpe1-Ix5vGbxbSZ3MQKKuaP More Text",
				matches: []string{"b2L1liMCcap6dKPMj_jKlrpe1-Ix5vGbxbSZ3MQKKuaP"},
			},
			{
				input:   "abcd \"ibm_keyid\": b2L1liMCcap6dKPMj_jKlrpe1-Ix5vGbxbSZ3MQKKuaP wxyz",
				matches: []string{"b2L1liMCcap6dKPMj_jKlrpe1-Ix5vGbxbSZ3MQKKuaP"},
			},
			{
				input:   "oh look a secret! 'cloudiampwd' + b2L1liMCcap6dKPMj_jKlrpe1-Ix5vGbxbSZ3MQKKuaP",
				matches: []string{"b2L1liMCcap6dKPMj_jKlrpe1-Ix5vGbxbSZ3MQKKuaP"},
			},
			{
				input:   "[CloudPassword] => b2L1liMCcap6dKPMj_jKlrpe1-Ix5vGbxbSZ3MQKKuaP",
				matches: []string{"b2L1liMCcap6dKPMj_jKlrpe1-Ix5vGbxbSZ3MQKKuaP"},
			},
			{
				input:   "It's my testPassword := b2L1liMCcap6dKPMj_jKlrpe1-Ix5vGbxbSZ3MQKKuaP",
				matches: []string{"b2L1liMCcap6dKPMj_jKlrpe1-Ix5vGbxbSZ3MQKKuaP"},
			},
			{
				input:   "['IBMTOKEN'] :: 'b2L1liMCcap6dKPMj_jKlrpe1-Ix5vGbxbSZ3MQKKuaP'",
				matches: []string{"b2L1liMCcap6dKPMj_jKlrpe1-Ix5vGbxbSZ3MQKKuaP"},
			},
			{
				input:   "    .set(\"apikey\", \"abcd1234abcd1234abcd1234ABCD1234ABCD1234--__\")",
				matches: []string{"abcd1234abcd1234abcd1234ABCD1234ABCD1234--__"},
			},
			{
				input:   "  authenticator = IAMAuthenticator('abcd1234abcd1234abcd1234ABCD1234ABCD1234--__')",
				matches: []string{"abcd1234abcd1234abcd1234ABCD1234ABCD1234--__"},
			},
		},
		"IBM_SOFTLAYER_API_KEY": {
			{
				input: `// curl -v https://ams01.objectstorage.softlayer.net/auth/v1.0/v1.0
				    -H "X-Auth-User: IBMOS111111-1:hellosoft"
					-H "X-Auth-Key: 26a84cd5dad20e0ae6ecd7daef2604d65127edd9d4ca2d9564607fde0aba9654"
					-H "Host: ams01.objectstorage.softlayer.net"
					-H "X-Auth-New-Token: true"
					-H "X-Auth-Token-Lifetime: 15"`,
				matches: []string{"26a84cd5dad20e0ae6ecd7daef2604d65127edd9d4ca2d9564607fde0aba9654"},
			},
			{
				input:   "knife[:softlayer_api_key]  = '26a84cd5dad20e0ae6ecd7daef2604d65127edd9d4ca2d9564607fde0aba9654'",
				matches: []string{"26a84cd5dad20e0ae6ecd7daef2604d65127edd9d4ca2d9564607fde0aba9654"},
			},
			{
				input:   "http://api.softlayer.com/soap/v3.1/06cef1beff5432cc9453934e06beb85de5f0a53a2340d7e0cd4a4705655e8132",
				matches: []string{"06cef1beff5432cc9453934e06beb85de5f0a53a2340d7e0cd4a4705655e8132"},
			},
			{
				input:   "https://api.softlayer.com/soap/v3/06cef1beff5432cc9453934e06beb85de5f0a53a2340d7e0cd4a4705655e8132",
				matches: []string{"06cef1beff5432cc9453934e06beb85de5f0a53a2340d7e0cd4a4705655e8132"},
			},
		},
		"IBM_SOFTLAYER_API_USERNAME": {
			{
				input:   "  --softlayer-username = test@testy.test",
				matches: []string{"test@testy.test"},
			},
			{
				input:   "softlayer_id = 'test2@testy.test'",
				matches: []string{"test2@testy.test"},
			},
			{
				input:   "sl-user = 'test2@testy.test'",
				matches: []string{"test2@testy.test"},
			},
			{
				input:   "SOFTLAYER_USERID = 'test3@testy.testy'",
				matches: []string{"test3@testy.testy"},
			},
			{
				input:   "softlayer-uname: notanemail",
				matches: []string{"notanemail"},
			},
			{
				input:   "NAME => it-is_a_name-i-think",
				matches: []string{"it-is_a_name-i-think"},
			},
			{
				input: `// curl -v https://ams01.objectstorage.softlayer.net/auth/v1.0/v1.0
				    -H "X-Auth-User: IBMOS321366-2:cloudsoft"
					-H "X-Auth-Key: 06cef1beff5432cc9453934e06beb85de5f0a53a2340d7e0cd4a4705655e8132"
					-H "Host: ams01.objectstorage.softlayer.net"
					-H "X-Auth-New-Token: true" -H "X-Auth-Token-Lifetime: 15"`,
				matches: []string{"IBMOS321366-2:cloudsoft"},
			},
		},
		"IBM_NAME_PRESENCE": {
			{input: "ibm"},
			{input: "IBM"},
			{
				input:   "['MYIBMTOKEN'] :: 'b2L1liMCcap6dKPMj_jKlrpe1-Ix5vGbxbSZ3MQKKuaP'",
				matches: []string{"IBM"},
			},
			{
				input:   "-H \"X-Auth-User: IBMOS111111-1:hellosoft\"",
				matches: []string{"IBM"},
			},
		},
		"IBM_SOFTLAYER_NAME_PRESENCE": {
			{input: "softlayer"},
			{input: "SoftLayer"},
			{input: "SOFTLAYER"},
			{
				input:   "SOFTLAYERKEY",
				matches: []string{"SOFTLAYER"},
			},
			{input: "ibm"},
			{input: "IBM"},
			{
				input:   "['MYIBMTOKEN'] :: 'b2L1liMCcap6dKPMj_jKlrpe1-Ix5vGbxbSZ3MQKKuaP'",
				matches: []string{"IBM"},
			},
			{
				input:   "-H \"X-Auth-User: IBMOS111111-1:hellosoft\"",
				matches: []string{"IBM"},
			},
		},
		"INSTAGRAM_VERY_TINY_ENCRYPTED_SESSION": {
			{input: "IGQVJVcGYyN2VscFVGa2s1eGpLcmU4UmxQWXJ5MmI1RDI1WjJXbVdwTG5wZAWU3bDNVWk0zTVFwWXctUm5PNENkUWFtWlVEeEJTdVJOd0s1a2JPNGtwT3UyTWJOaUVueFhfU2Q5S3JR"},
		},
		"INTERCOM_ACCESS_TOKEN": {
			{input: "dG9rOmJmNGQ2Y2ViX2I1ZmVfNDE2Zl9iZGJlXzY3ODNiYzIxZGYzMzoxOjA="},
		},
		"IONIC_PERSONAL_ACCESS_TOKEN": {
			{
				input:   "Bearer ion_9nkEOcIGqfd4I6ntgdOSZ44ZC9hdQvlhOl8m",
				matches: []string{"ion_9nkEOcIGqfd4I6ntgdOSZ44ZC9hdQvlhOl8m"},
			},
		},
		"IONIC_PERSONAL_ACCESS_TOKEN_WITH_CHECKSUM": {
			{
				input:   "Bearer ion_39lOSy19nhsltDatoyV3VTBrBqnQVlCTPkln2pNt8M",
				matches: []string{"ion_39lOSy19nhsltDatoyV3VTBrBqnQVlCTPkln2pNt8M"},
			},
			{
				input:   "Bearer ion_An6twkr8NTZlSxcKYDGdh8iAzzkORJCa7i9K3vG0wU",
				matches: []string{"ion_An6twkr8NTZlSxcKYDGdh8iAzzkORJCa7i9K3vG0wU"},
			},
			{
				input:   "Bearer ion_3KyAeytvw8lETsDHXDqBjQHE8fe0mx1QLHcH32IZLN",
				matches: []string{"ion_3KyAeytvw8lETsDHXDqBjQHE8fe0mx1QLHcH32IZLN"},
			},
			{
				input:   "Bearer ion_YFimjeGVVgVdj3EadcLwfqCvElUXO2jGNEQj3OVwGc",
				matches: []string{"ion_YFimjeGVVgVdj3EadcLwfqCvElUXO2jGNEQj3OVwGc"},
			},
			{
				input:   "Bearer ion_y1MUR0Xej4yD0qhsjCoh5w7ClkKHkbbijeZP2YiF6J",
				matches: []string{"ion_y1MUR0Xej4yD0qhsjCoh5w7ClkKHkbbijeZP2YiF6J"},
			},
		},
		"IONIC_REFRESH_TOKEN": {
			{
				input:   "Bearer ion_rbkXC3fmUxCydQDOZBHQIxAdVbk5YJZeGOJgrbkXC3fmUxCy",
				matches: []string{"ion_rbkXC3fmUxCydQDOZBHQIxAdVbk5YJZeGOJgrbkXC3fmUxCy"},
			},
		},
		"IONIC_REFRESH_TOKEN_WITH_CHECKSUM": {
			{
				input:   "Bearer ion_wWBzaYDOOnYlwV4CtiR1Uzf78OInjvBcmSDijL4kKcPLVoIw3oNw6q",
				matches: []string{"ion_wWBzaYDOOnYlwV4CtiR1Uzf78OInjvBcmSDijL4kKcPLVoIw3oNw6q"},
			},
			{
				input:   "Bearer ion_EP9AdE3LQjbqqOWn0WrpRCpnhJwTFZS4xw2tMsABL3MDXXly0NyC2P",
				matches: []string{"ion_EP9AdE3LQjbqqOWn0WrpRCpnhJwTFZS4xw2tMsABL3MDXXly0NyC2P"},
			},
			{
				input:   "Bearer ion_mCFexJIykvqFivFVtc0XDTtY7Z2o6tLXYix05pY6hi6eO9K50bZVuq",
				matches: []string{"ion_mCFexJIykvqFivFVtc0XDTtY7Z2o6tLXYix05pY6hi6eO9K50bZVuq"},
			},
			{
				input:   "Bearer ion_HVLVe79FhkNxFAbIg4hCWdGXUNWK8oTiDi3AhlsCz0DqBM7T29AZDR",
				matches: []string{"ion_HVLVe79FhkNxFAbIg4hCWdGXUNWK8oTiDi3AhlsCz0DqBM7T29AZDR"},
			},
			{
				input:   "Bearer ion_Hu7RbBoXJEsOFVySc49KPl0P1GVfRuUf6XRrgN9w2TZGOpQY3WFGzo",
				matches: []string{"ion_Hu7RbBoXJEsOFVySc49KPl0P1GVfRuUf6XRrgN9w2TZGOpQY3WFGzo"},
			},
		},
		"JD_CLOUD_ACCESS_KEY": {
			{input: "JDCTBF0A7DFC4515E8BA3F6D0E9460BD"},
			{input: "JDC_BF0A7DFC4515E8BA3F6D0E9460BD"},
			{input: "JDCPBF0A7DFC4515E8BA3F6D0E9460BD"},
			{input: "JDCHBF0A7DFC4515E8BA3F6D0E9460BD"},
		},
		"JFROG_PLATFORM_API_KEY": {
			{input: "AKCp8jRS3bvDWu7XTjBbmNQXp3whY96Fr69aRUMBFSPP6TCGjXaNSLQFXs2k81oo2RRMRd1Cf"},
		},
		"LAUNCHDARKLY_ACCESS_TOKEN": {
			// Generated from https://app.launchdarkly.com/settings/authorization
			{input: "api-8398baf0-2fe5-42ee-b135-b24091c68f58"},
		},
		"LINEAR_API_KEY": {
			{
				input:   "Bearer lin_api_neH3Dbir9oUTewyqldy8zvmnHcQAH3qnuY2aG0ok",
				matches: []string{"lin_api_neH3Dbir9oUTewyqldy8zvmnHcQAH3qnuY2aG0ok"},
			},
			{
				input:   "Bearer lin_api_FU7us8Zz81Xv5kfdkxp6Fkx0wAycTq1icRKHHHTK",
				matches: []string{"lin_api_FU7us8Zz81Xv5kfdkxp6Fkx0wAycTq1icRKHHHTK"},
			},
		},
		"LINEAR_OAUTH_ACCESS_TOKEN": {
			{
				input:   "Bearer lin_oauth_75179742c6bb4019ac3d81325de8d5f08a4c2bea2f4df0c995aa3db9f2230d4c",
				matches: []string{"lin_oauth_75179742c6bb4019ac3d81325de8d5f08a4c2bea2f4df0c995aa3db9f2230d4c"},
			},
			{
				input:   "Bearer lin_oauth_b93556b05d4e4d1e39608db71b43d51de637e97594784093b43f1800ee81056b",
				matches: []string{"lin_oauth_b93556b05d4e4d1e39608db71b43d51de637e97594784093b43f1800ee81056b"},
			},
		},
		"LOB_LIVE_API_KEY": {
			// Generated from https://dashboard.lob.com/#/settings/keys
			{input: "live_a6e23251ae5357dd177d864cdd07c3dbe42"},
		},
		"LOB_TEST_API_KEY": {
			// Generated from https://dashboard.lob.com/#/settings/keys
			{input: "test_a7c6931f99dcc4ff1be56c4c25aa40cf574"},
		},
		"LOCALSTACK_API_KEY": {
			{input: "LOCALSTACK_API_KEY=keoD4ief"},
			{input: "LOCALSTACK_API_KEY=3jaLBCq92g"},
			{input: "LOCALSTACK_API_KEY=daxail7Aim"},
			{input: "LOCALSTACK_API_KEY=iuDaemei8uu6"},
			{input: "LOCALSTACK_API_KEY=eRie0yi7faed"},
		},
		"LOGICMONITOR_BEARER_TOKEN": {
			{input: "lmb_SkRJNXRzZkFUWGo0SXV3M0YzdjQ6ZU04dFpMVW5iNEpvV0NFeFEyWTdmdz09LYWViYjc3MjEtYTU1Mi00ZTcyLWFjYTQtOGZjYTNjMTA4Njc0L1hlRaK"},
			// Modified provided LOGICMONITOR_LMV1_ACCESS_KEY's prefix
			{input: "lmb_2N6bJzq}Cn8w37J[-]X~H7s8h9^^U{6mf7cW+6D34%)H2U4=TM2L7+%P8e5CLYWViYjc3MjEtYTU1Mi00ZTcyLWFjYTQtOGZjYTNjMTA4Njc0L0swEl7"},
		},
		"LOGICMONITOR_LMV1_ACCESS_KEY": {
			{input: "lma_2N6bJzq}Cn8w37J[-]X~H7s8h9^^U{6mf7cW+6D34%)H2U4=TM2L7+%P8e5CLYWViYjc3MjEtYTU1Mi00ZTcyLWFjYTQtOGZjYTNjMTA4Njc0L0swEl7"},
			// Modified provided LOGICMONITOR_BEARER_TOKEN's prefix
			{input: "lma_SkRJNXRzZkFUWGo0SXV3M0YzdjQ6ZU04dFpMVW5iNEpvV0NFeFEyWTdmdz09LYWViYjc3MjEtYTU1Mi00ZTcyLWFjYTQtOGZjYTNjMTA4Njc0L1hlRaK"},
		},
		"PLIVO_AUTH_ID": {
			{input: "MAMZKYYTA1ZJU1ZDI4ZJ"},
			{input: "SAMZKYYTA1ZJU1ZDI4ZJ"},
			{input: "MAMTKYYWM1YTU1ZDIYZW"},
		},
		"PLIVO_AUTH_TOKEN": {
			{input: "YTM5ZTQ3ZjA0N2ZkOTJiZjk5MTljNmZjYzJmOWEy"},
		},
		"MAILCHIMP_API": {
			{input: "08f5db9707e601e6c1a389c6cd9e1f94-us2"},
		},
		"MAILGUN": {
			// newer style mailgun token
			{input: "fda577e4fea861b6b030e6c6e18ce153-1b65790d-042e842d"},
		},
		"MAILGUN_LEGACY": {
			// older style mailgun token
			{input: "key-a32ba0a5a10a749d4537edfbd5c5ffd4"},
			{input: "key-55B4EB1490AEC3D5C78359909ED38EF0"},
		},
		"MAILGUN_SMTP": {
			// catch cases where smtp username+password checked in, by looking for smtp.mailgun.org
			{
				input:   "MAILGUN_SMTP_PORT: '587'\nMAILGUN_SMTP_SERVER: smtp.mailgun.org\nMAILGUN_SMTP_LOGIN: postmaster@testing123.org\nMAILGUN_SMTP_PASSWORD: 1-a4h-1fxd66\n",
				matches: []string{"smtp.mailgun.org"},
			},
			{
				input:   "server: SMTP.MAILGUN.ORG\nusername: someuser\npassword: somepassword",
				matches: []string{"SMTP.MAILGUN.ORG"},
			},
		},
		"MANDRILL_API": {
			{
				input:   "mandrill: \"Ghx1muYYFF4Zzy2fjmVU7g\"",
				matches: []string{"Ghx1muYYFF4Zzy2fjmVU7g"},
			},
			{
				input:   "MANDRILL: 'Ghx1muYYFF4Zzy2fjmVU7g'",
				matches: []string{"Ghx1muYYFF4Zzy2fjmVU7g"},
			},
			{
				input:   "mandrill: `Ghx1muYYFF4Zzy2fjmVU7g`",
				matches: []string{"Ghx1muYYFF4Zzy2fjmVU7g"},
			},
			{
				input:   "Mandrill: Ghx1muYYFF4Zzy2fjmVU7g",
				matches: []string{"Ghx1muYYFF4Zzy2fjmVU7g"},
			},
			{
				input:   "mandrill:Ghx1muYYFF4Zzy2fjmVU7g",
				matches: []string{"Ghx1muYYFF4Zzy2fjmVU7g"},
			},
			{
				input:   "ManDrill=Ghx1muYYFF4Zzy2f-mVU7g",
				matches: []string{"Ghx1muYYFF4Zzy2f-mVU7g"},
			},
			{
				input:   "mandrill =Ghx1muYYFF4Zzy2f-mVU7g",
				matches: []string{"Ghx1muYYFF4Zzy2f-mVU7g"},
			},
			{
				input:   "MANDRILL= Ghx1muYYFF4Zzy2f-mVU7g",
				matches: []string{"Ghx1muYYFF4Zzy2f-mVU7g"},
			},
			{
				input:   "mandrill = Ghx1muYYFF4Zzy2f-mVU7g",
				matches: []string{"Ghx1muYYFF4Zzy2f-mVU7g"},
			},
			{
				input:   "MaNdRiLl == Ghx1muYYFF4Zzy2f-mVU7g",
				matches: []string{"Ghx1muYYFF4Zzy2f-mVU7g"},
			},
			{
				input:   "mandrill === Ghx1muYYFF4Zzy2f-mVU7g",
				matches: []string{"Ghx1muYYFF4Zzy2f-mVU7g"},
			},
			{
				input:   "MANDRILL Ghx1muYYFF4Zzy2fjmVU7g\"",
				matches: []string{"Ghx1muYYFF4Zzy2fjmVU7g"},
			},
			{
				input:   "mandrill   =   Ghx1muYYFF4Zzy_fjmVU7g",
				matches: []string{"Ghx1muYYFF4Zzy_fjmVU7g"},
			},
			{
				input:   "my_mandrill_secret=\"Ghx1muYYFF4Zzy2fjmVU7g\"",
				matches: []string{"Ghx1muYYFF4Zzy2fjmVU7g"},
			},
			{
				input:   "MANDRILLSECRET:'Ghx1muYYFF4Zzy2f-mVU7g'",
				matches: []string{"Ghx1muYYFF4Zzy2f-mVU7g"},
			},
			{
				input:   "manDrillApi: Ghx1muYYFF4Zzy_fjmVU7g",
				matches: []string{"Ghx1muYYFF4Zzy_fjmVU7g"},
			},
			{
				input:   "mandrill-secret = `Ghx1muYYFF4Zzy2fjmVU7g`",
				matches: []string{"Ghx1muYYFF4Zzy2fjmVU7g"},
			},
			{
				input:   "mandrill = Ghx1muYYFF4Zzy2fjmVU7g;",
				matches: []string{"Ghx1muYYFF4Zzy2fjmVU7g"},
			},
			// From partner
			{
				input:   "a_mandrilltest_key = 1a31231231231231231231",
				matches: []string{"1a31231231231231231231"},
			},
			{
				input:   "MandrIll_key =123123123f231231231231",
				matches: []string{"123123123f231231231231"},
			},
			{
				input:   "MandrIll_key: `12312312z1231231231231`",
				matches: []string{"12312312z1231231231231"},
			},
			{
				input:   "MandrIll_key:= '12312312z1231231231231'",
				matches: []string{"12312312z1231231231231"},
			},
			{
				input:   "mandrIll_te-st_key=\"123s231231-3_231231231\"",
				matches: []string{"123s231231-3_231231231"},
			},
		},
		"MANDRILL_API_V2": {
			{input: "md-y1PoZZAvROBr5CkIB26CaQ"},
			{input: "md-C9dw8ZeMJOPpFk7IGPHOWg"},
			{input: "md-WxmJYy8KtH8ZjXogHL7lVg"},
			{
				input:          `class="md-footer-nav__link md-footer-nav__link--next"`,
				shouldNotMatch: true,
			},
		},
		"MAPBOX_SECRET_ACCESS_TOKEN": {
			{input: "sk.eyJ1IjoiZ3JleXN0ZWlsIiwiYSI6ImNrdjVmdW81bzExd3Eydm8wdXFrbGV1emYifQ.a4jLghDBKQkWOlBXFzklEA"},
		},
		"MERCURY_NON_PRODUCTION_API_TOKEN": {
			{
				input:   "secret-token:mercury_pentest_wma_2DTRdLi1ZZhHGp4KmBUj63cwzNKk3rwTUanqCWzmQykurg_yrucrem",
				matches: []string{"mercury_pentest_wma_2DTRdLi1ZZhHGp4KmBUj63cwzNKk3rwTUanqCWzmQykurg_yrucrem"},
			},
			{
				input:   "secret-token:mercury_local_wma_3h1d8WVWik8Nz6WQiyU3iRtw2ru9DMNbjL73WzDEukfoH_yrucrem",
				matches: []string{"mercury_local_wma_3h1d8WVWik8Nz6WQiyU3iRtw2ru9DMNbjL73WzDEukfoH_yrucrem"},
			},
			{
				input:          "secret-token:mercury_production_wma_yRkHf7HMUZDAa83LQ8mCaseLEvRYArvZuunisbz5QoHB8_yrucrem",
				shouldNotMatch: true,
			},
		},
		"MERCURY_PRODUCTION_API_TOKEN": {
			{
				input:   "secret-token:mercury_production_rma_kzb3M8CRR7Wau2N1AWEVn2nfBCGBo29MDrsH7L3Dkc7vk_yrucrem",
				matches: []string{"mercury_production_rma_kzb3M8CRR7Wau2N1AWEVn2nfBCGBo29MDrsH7L3Dkc7vk_yrucrem"},
			},
			{
				input:   "secret-token:mercury_production_rpa_L4b3F9Cwp3Kbu320MwsVnonfGCGIo53DDUWc7s3DIc7Qz_yrucrem",
				matches: []string{"mercury_production_rpa_L4b3F9Cwp3Kbu320MwsVnonfGCGIo53DDUWc7s3DIc7Qz_yrucrem"},
			},
			{
				input:   "secret-token:mercury_production_wma_yRkHf7HMUZDAa83LQ8mCaseLEvRYArvZuunisbz5QoHB8_yrucrem",
				matches: []string{"mercury_production_wma_yRkHf7HMUZDAa83LQ8mCaseLEvRYArvZuunisbz5QoHB8_yrucrem"},
			},
			{
				input:          "secret-token:mercury_local_wma_3h1d8WVWik8Nz6WQiyU3iRtw2ru9DMNbjL73WzDEukfoH_yrucrem",
				shouldNotMatch: true,
			},
		},
		"MESSAGEBIRD_NAME_PRESENCE": {
			{input: "mSgBiRd"},
			{input: "MESSAGEbird"},
			{input: "MESSAGEBIRD"},
			{input: "msgbird"},
		},
		"MESSAGEBIRD_TOKEN": {
			{input: "qH2u4OSx1jmTVWgBBMzS3uAMQ"},
			{input: "4hr42b0g9s3tKbRjdY8mv6Hp5"},
			{input: "live_KY6kQJTfBesSrhXsNtGLaAKDu"},
			{input: "test_UHaeiTLfAe3avOULhawXvn7iR"},
		},
		"MICROSOFT_VSTS_PAT": {
			{input: "4ekvoj6ggsvgeac2nj7xbmnkmudqat3eta42aomb266b7clwmnta"},
		},
		"MICROSOFT_AZURE_BATCH_KEY_IDENTIFIABLE": {
			{input: "mShU70sV70jFdGStetTXsfOO49XRObwfkf/XrVMP5L3qYXSj9SAIai93EPaU+WvGLDE6Yzs8JPXw+ABaJa71+g=="},
		},
		"MICROSOFT_AZURE_CONTAINER_REGISTRY_KEY_IDENTIFIABLE": {
			{input: "FC2AMuwowKl/uDXJFIlGz9w1BNjySol4v+RdNepLi5+ACRDX2yNC"},
		},
		"MICROSOFT_AZURE_COSMOSDB_KEY_IDENTIFIABLE": {
			{input: "zu7v6VYcpROkO1ipGAEiroNsc4GLB07HfLXg4sA9R8R8CJOg4kZ2Mr83Pd2G4XzfpMj7wRvhhzbsACDbp9B2jw=="},
			{input: "gGiiqmi8N7Am4SyOuCt43PUWdJswbpbUvDB4hwyCg0ZMVxUBZbQQlMvaAVjLovTVYI5I5DsK8Y5bACDbN8bILw=="},
			{input: "9OiSaUpoZPbba03U8fB8ue8AjY5JGBONSV54rhF7xFwvKJJ1Pzu7BTcfsyjkyn2EnKXvMg99WQ5TACDb9202qg=="},
			{input: "D33d7Ju7aMzUjUPLHOi9Q2LW6r1Y5HIrtb6dyl8CDvIiZ8WAQvwso2YvuGKto2EFoepAQYvSYAXPACDbdFZoyg=="},
		},
		"MICROSOFT_AZURE_COSMOSDB_INTERNAL_SECRET_IDENTIFIABLE": {
			{input: "HYwpJl36iTJtfrfRp9cpoPxiKI1RsXHO9LssvfjToaOD3b+mn+66dLu0v0gRdjCZdqsXYRxunFbgACDbDpSZ5A=="},
			{input: "LK9ERnulMZUnGc4jGAXGEOXBFw0gNvQ13/pXJ5NfjaUmVwv3FleunH5VNFgwwS0ASCViY+A7lTmGACDbF2WM2Q=="},
			{input: "Vwxqz9QzkPPWbWuSy+Ua9P7DDM5ojCseNN6i9PfB0ZFNsyUkYxcwIcAPHDf/yeJfvp9hN+d48bX9ACDbqoCr4w=="},
			{input: "KwaLYJckAMCITSbgov3v1AQ4QvvZRo4i55svR/yc5gat+PlCkZckIYs4oW3tBug0duZ3Suz4RkxXACDbT7fVYw=="},
			{input: "wPOZ0TuF/A9mWl28fSgUDQxwafG/3rWE1HRy/3RQduqhTxB++g6c58zU+Xr/y8zLPCVob3HECYkQACDb4yo+HA=="},
			{input: "cY3HNftlj1dDI0plMiM6Un7ksPbj9VeLXDqq6DM3XL8+45fQ35SMtrdhtKlW+MTrisySE6ISJVkpACDbQS9pXQ=="},
			{input: "yoiR+qEZVnQF55KOffDU1vHPVZSwfjhc/ACDbClvaMY="},
			{input: "I0ZFBrKIhsXLnWzziYBkf5+58f7NMxxFzACDbDWqIfc="},
		},
		"MICROSOFT_AZURE_EVENT_HUB_INTERNAL_SECRET_IDENTIFIABLE": {
			{input: "8NsvZep5Y+idaX1WK/P1kpgjzbuFOKedK+AEhClJdOw="},
			{input: "LXuMNJ30ech6YWTm24cUg4H84SwwZDPtxARp1+nbvO+AEhDwjVUA"},
		},
		"MICROSOFT_AZURE_EVENT_HUB_KEY_IDENTIFIABLE": {
			{input: "eGSI2hwb8BQ3CQU57TLoWI8TszlNUGutq+AEhE6eHgQ="},
			{input: "g6gw2YhnWpppbGZ0SRyRveSIHBrvx5Lkf+AEhCnTNf0="},
			{input: "xZYJqONYR1jnqxskucQJGznjbWybLGjfv+AEhOpLP+g="},
			{input: "wGAP/HCWh5i1LVerHpkTuwBYBvQA8H0Yf9hW13+Qxn+AEhCm7T47"},
			{input: "JgbdfW7N2e22tmsJyEdSPV+oqYFxa/zknoFWGuNu8S+AEhBdICpN"},
			{input: "qF94sQIQJEqXxL5TC/PaTVIIhBHVBshhEKejxp0mR7+AEhDrsxMy"},
		},
		"MICROSOFT_AZURE_RELAY_KEY_IDENTIFIABLE": {
			{input: "USn+18CwdqN5qRzQEGXaIhRz3Rb7CF+/H+ARmIVMeLM="},
			{input: "FUk78i6KCRTQ6qzDhMbo3QzZOrtmoPVfc+ARmKoDElE="},
			{input: "1d2R5D7mg8Z9CGMmUzVN0KnXapAkOrdoN+ARmAjKiec="},
			{input: "BOvIRW17AxWyUzxYHFwSAiUGHBrS95F6Ii/P4KM4bQ+ARmC90gS3"},
			{input: "vCJTlN78YQXj6vye3m/xiKB7w9SUBoyRI/g3T5BFq0+ARmCNJDbw"},
			{input: "FMTM+nVm6/MB0Xg9gGuMiY1HJ5Gj9qkSxMg1BrzB5Y+ARmC0nZ2N"},
		},
		"MICROSOFT_AZURE_SAS_TOKEN_LOOSE": {
			{
				input:   "http://test.blob.core.windows.net/test/test.vhd?sr=c&si=test&sig=abcdefghijklmnopqrstuvwxyz0123456789%F%2BABCDE%3D",
				matches: []string{"sig=abcdefghijklmnopqrstuvwxyz0123456789%F%2BABCDE%3D"},
			},
			{
				input:   "http://test.blob.core.windows.net/test/test.vhd?sr=c&si=test&sig=abcdefghijklmnopqrstuvwxyz0123456789%F%2BABCDE%3d",
				matches: []string{"sig=abcdefghijklmnopqrstuvwxyz0123456789%F%2BABCDE%3d"},
			},
		},
		"MICROSOFT_AZURE_STORAGEACCOUNTKEY_V1": {
			{
				input:   "AccountName=devstoreaccount1;AccountKey=Eby8vdM02xNOcqFlqUwJPLlmEtlCDXJ1OUzFT50uSRZ6IFsuFq2UVErCz4I6tq/K1SZFPTOtr/KBHBeksoGMGw==",
				matches: []string{"Eby8vdM02xNOcqFlqUwJPLlmEtlCDXJ1OUzFT50uSRZ6IFsuFq2UVErCz4I6tq/K1SZFPTOtr/KBHBeksoGMGw=="},
			},
			{
				input:          "Eby8vdM02xNOcqFlqUwJPLlmEtlCDXJ1OUzFT50uSRZ6IFsuFq2UVErCz4I6tq/K1SZFPTOtr/KBHBeksoGMGw==",
				shouldNotMatch: true,
			},
		},
		"MICROSOFT_AZURE_ML_WEB_SERVICE_CLASSIC_IDENTIFIABLE_KEY": {
			{input: "9EDvU/rksIFpFxcRU1rkWbOnxcesrOq/xSpXQIg8A6uUQWlDQDykINFTiQp5lg6vtyJ9SAwFgbdz+AMCdq7pCA=="},
		},
		"MICROSOFT_AZURE_STORAGE_ACCOUNT_ACCESS_KEY": {
			{input: "Eby8vdM02xNOcqFlqUwJPLlmEtlCDXJ1OUzFT50uSRZ6IFsuFq2UVErCz4I6tq/K1SZFPTOtr/KBHBeksoGMGw=="},
		},
		"MICROSOFT_AZURE_STORAGE_ACCOUNT_ACCESS_KEY_IDENTIFIABLE": {
			{input: "U1imXW0acA5QRtnkKuW14QPSC/F1JFS9mOjd8Ny/Muab42CVkI8G0/ja7uM13GlfiS8pp4c/kzYp+AStvBjS1w=="},
		},
		"MICROSOFT_AZURE_SEARCH_QUERY_KEY_IDENTIFIABLE": {
			{input: "Ehfj5EkHrLAxxjsio6nOvLjMwq8obwjQ54irCfb80lAzSeDB1IxJ"},
		},
		"MICROSOFT_AZURE_SEARCH_ADMIN_KEY_IDENTIFIABLE": {
			{input: "VLcGD3bO4PSPaKs4sKiSvZCadPn1h0xVrx4BmTBluYAzSeDgB3x1"},
		},
		"MICROSOFT_AZURE_SEARCH_INTERNAL_SECRET_IDENTIFIABLE": {
			{input: "shx3Gef0ERW9wbkjACO33IcK9vBdqWaRvhP63pNVURAzSeDvbD6N"},
			{input: "Xhfj5EkHrLAxxjsio6nOvLjMwq8obwjQ54irCfb80lAzSeDB1IxJ"},
			{input: "XLcGD3bO4PSPaKs4sKiSvZCadPn1h0xVrx4BmTBluYAzSeDgB3x1"},
		},
		"MICROSOFT_AZURE_SERVICE_BUS_KEY_IDENTIFIABLE": {
			{input: "OLh8td/lQT+RCNRtJPEMXLSmycWxb2vAU+ASbFpQcYg="},
			{input: "ffncxrWUwqHaorytze25VG76PDqKOOGYh+ASbDctxAc="},
			{input: "dMhifcnQ79k8sDvj+N+kiW3JSz04Z1mh7+ASbA7Ix4M="},
			{input: "28F6ALxqI3wzXXnlIRHIlfW3Hdtpw5fhmDXrelvm11+ASbBmkXZQ"},
			{input: "oI6jzdLvu3AvUa9qjHP8YFHeoPlfKpOcvN0oBVZq52+ASbBCcy3W"},
			{input: "IlQ4IG8Q0BTc+/7SO40A8oshOMcL8Mjw4/ZgCVOC/w+ASbCpPKvu"},
		},
		"MICROSOFT_AZURE_SERVICE_BUS_INTERNAL_SECRET_IDENTIFIABLE": {
			{input: "T47+otBxVdkVlAFCKGU1OyVHkV3EZ7HcT+ASbG0AzgQ="},
			{input: "T37l/+20DmaNmvumxpTJCtGGVO1dYvyKhWTyo9Qn0O+ASbArU5fK"},
		},
		"MICROSOFT_AZURE_STORAGE_INTERNAL_SECRET_IDENTIFIABLE": {
			{input: "A1Y3QmJoHE1DMSL2L2Lejbr/xdHOXGAeRi2mTvCw8q1QBlnmz1BX8AehUgtijgYcPLu7sYPUf2Ut+AStcztz3A=="},
			{input: "KTrXxAZ8gjHFzlOEByEFDzoXtkLatxjzr+AStDbIOWg="},
		},
		"MICROSOFT_AZURE_SQLCONNSTR_V1": {
			{
				input:   "Data Source=tcp:aaa.database.windows.net,1433;Initial Catalog=bbb;Integrated Security=False;User ID=ccc@aaa;Password=ddd;",
				matches: []string{"aaa.database.windows.net"},
			},
			{
				input:   "jdbc:sqlserver://aaa.database.chinacloudapi.cn:1433",
				matches: []string{"aaa.database.chinacloudapi.cn"},
			},
		},
		"MICROSOFT_AZURE_SUBMGMTCERT_V1": {
			{
				input:   "ManagementCertificate=\"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\"",
				matches: []string{"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"},
			},
			{
				input:          "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",
				shouldNotMatch: true,
			},
		},
		"MICROSOFT_SAS_TOKEN": {
			{
				input:   "http://test.blob.core.windows.net/test/test.vhd?sr=c&si=test&sig=abcdefghijklmnopqrstuvwxyz0123456789%F%2BABCDE%3D",
				matches: []string{"abcdefghijklmnopqrstuvwxyz0123456789%F%2BABCDE%3D"},
			},
			{
				input:   "http://test.blob.core.windows.net/test/test.vhd?sr=c&si=test&sig=abcdefghijklmnopqrstuvwxyz0123456789%F%2BABCDE%3d",
				matches: []string{"abcdefghijklmnopqrstuvwxyz0123456789%F%2BABCDE%3d"},
			},
		},
		"MICROSOFT_AZURE_SHARED_ACCESS_KEY": {
			{
				input:   "SharedAccessKey=NNz/uMj5QjHcbJQidfa+xL6KVGpDGeJ2AtN2XUWPLkA=",
				matches: []string{"NNz/uMj5QjHcbJQidfa+xL6KVGpDGeJ2AtN2XUWPLkA="},
			},
			{
				input:   "sharedaccesskey=NNz/uMj5QjHcbJQidfa+xL6KVGpDGeJ2AtN2XUWPLkA=",
				matches: []string{"NNz/uMj5QjHcbJQidfa+xL6KVGpDGeJ2AtN2XUWPLkA="},
			},
		},
		"MICROSOFT_AAD_USER_CREDENTIAL": {
			{input: "Foo.bar.9@microsoft.com"},
			{input: "foo_BAR_9@baz.miCROsoft.com"},
			{input: "foo-bar-9@baz.onmicrosoft.com"},
		},
		"MICROSOFT_CREDENTIAL_PASSWORD": {
			{input: "password"},
			{input: "pwd"},
			{input: "db_pass"},
			{input: "DB_PASS"},
			{input: "PASSWORD"},
			{input: "PWD"},
		},
		"MICROSOFT_INTERNAL_ACTIVE_DOMAIN_USER_CREDENTIAL": {
			{input: "redmond\\abc.def.ghi.jkl"},
			{input: "ntdev\\v-notarealaccount"},
			{input: "cme.gbl\\notarealuser"},
			{input: "prod\\notarealaccount"},
			{input: "Ignore encoded ampersand: Redmond\u0026.", shouldNotMatch: true},
			{input: "Ignore space after newline: We use Exchange\n at our company.", shouldNotMatch: true},
			{input: "Ignore non-vowel after newline: We use Exchange\nfor sending email.", shouldNotMatch: true},
		},
		"MICROSOFT_AZURE_DEPLOYMENT_PASSWORD": {
			{input: "userPWD=abcdefghijklmnopqrstuvwxyz0123456789/+ABCDEFGHIJKLMNOPQRSTUV"},
			{
				input:   "<PublishingPassword>abcdefghijklmnopqrstuvwxyz0123456789/+ABCDEFGHIJKLMNOPQRSTUV</PublishingPassword>",
				matches: []string{"PublishingPassword\u003eabcdefghijklmnopqrstuvwxyz0123456789/+ABCDEFGHIJKLMNOPQRSTUV"},
			},
		},
		"MICROSOFT_AAD_APPLICATION_KEY": {
			{input: "M_2POXv6_j~vcLq0LT~T5IrpCuk69U.248"},
			{input: ".rCMJScwqI_1~p0N-SgJ51JI-13JWALa1L"},
			{input: "--E3LU00XaU5T8ea-_LWujQ.pfi9sB17aX"},
			{input: "6cUU.C7klJipN~Dd6fyT05flAjW.78~~LO"},
		},
		"MICROSOFT_AAD_APPLICATION_KEY_IDENTIFIABLE_V1": {
			{input: "itR7Q~VlZiWg6iasIi13uDtyu8KVc.OQpxKER"},
			{input: "jFx7Q~MASkIwfrcqODqYQWZK2XGspZrsaOMEZ"},
			{input: "-_~7Q~pwJEZR2jXij5tko1my3LeJdB2no7Kcw"},
		},
		"MICROSOFT_AAD_APPLICATION_KEY_IDENTIFIABLE_V2": {
			{input: "A048Q~g6-N-06_1-1~f6.9-7M81_8du0.o~_OcU."},
		},
		"MICROSOFT_AZURE_WEB_APP_BOT_PASSWORD": {
			{
				input:   "\"MicrosoftAppPassword\": \"-]5+DnvuItdyJu44l6F8a+>}nod&2M\"",
				matches: []string{"-]5+DnvuItdyJu44l6F8a+>}nod&2M"},
			},
		},
		"MICROSOFT_OFFICE_INCOMING_WEBHOOK": {
			{input: "https://microsoft.webhook.office.com/webhookb2/79a1efce-d585-4dff-a6de-cd0685dedb5d@72f988bf-86f1-41af-91ab-2d7cd011db47/IncomingWebhook/1bfe186c815a4e0281f2b74e55442cc8/30165b06-8cc2-49da-938d-e00658ccc86a"},
		},
		"MICROSOFT_AZURE_KEYWORD": {
			{input: "azure"},
			{input: "Azure"},
			{input: "AZURE"},
			{input: "AzureBlob", matches: []string{"Azure"}},
		},
		"MICROSOFT_AZURE_APP_KEYWORDS": {
			{input: "appid"},
			{input: "appkey"},
			{input: "tenant"},
			{input: "APPID"},
			{input: "APPKEY"},
			{input: "TENANT"},
			{input: "client_secret"},
		},
		"MICROSOFT_AZURE_CACHE_FOR_REDIS_DOMAIN": {
			{
				input:   "mydomain.redis.cache.windows.net:6379",
				matches: []string{"redis.cache.windows.net"},
			},
		},
		"MICROSOFT_AZURE_CACHE_FOR_REDIS_ACCESS_KEY": {
			{input: "WJVIjw+lkihFxwo8U33+v+viGKFnaR6oGRf3fnJzMfs="},
			{input: "BZyVDBpSj81pVJelqqPrCOhUVBomugPTxDTVbg7V2IY="},
		},
		"MICROSOFT_AZURE_CACHE_FOR_REDIS_ACCESS_KEY_IDENTIFIABLE": {
			{input: "cThIYLCD6H7LrWrNHQjxhaSBu42KeSzGlAzCaNQJXdA="},
			{input: "Z77gHBkazVRFudtuKusPWuLMN77Ju2OUKAzCaLPQNsw="},
			{input: "rKyBcjtmxw0UOL2Wg7zUGaUb7TeqliK8aAzCaM4F4bM="},
			{
				input:   "redis://rKyBcjtmxw0UOL2Wg7zUGaUb7TeqliK8aAzCaM4F4bM=@my.redis.cache.windows.net",
				matches: []string{"rKyBcjtmxw0UOL2Wg7zUGaUb7TeqliK8aAzCaM4F4bM="},
			},
		},
		"MICROSOFT_AZURE_CACHE_FOR_REDIS_INTERNAL_SECRET_IDENTIFIABLE": {
			{input: "rKyBcjtmxw0UOL2Wg7zUGaUb7TeqliK8aAzCaM4F4bX="},
			{input: "fbQqSu216MvwNaquSqpI8MV0hqlUPgGChOY19dc9xDRMAzCaixCYbQ"},
		},
		"MICROSOFT_AZURE_COGNITIVE_SERVICES_DOMAIN": {
			{input: "grey-test.cognitiveservices.azure.com"},
		},
		"MICROSOFT_AZURE_COGNITIVE_SERVICES_KEY": {
			{input: "ca47dad862af4634801578640686a83e"},
		},
		"MICROSOFT_AZURE_CONTAINER_REGISTRY_DOMAIN": {
			{input: "greysteil.azurecr.io"},
		},
		"MICROSOFT_AZURE_CONTAINER_REGISTRY_ACCESS_KEY": {
			{input: "BF4uuby59n=qWLNzpJQrDfy8ZXBbGent"},
			{input: "AObFz+jOQf1MKtnD9qwIsMaCgAhUOCCX"},
			{input: "/xMUHvOfaQbjtaT6Tpe9WS9J92NPlrOE"},
		},
		"MICROSOFT_AZURE_COSMOS_DB_DOMAIN": {
			{input: "grey-test.documents.azure.com"},
		},
		"MICROSOFT_AZURE_COSMOS_DB_KEY": {
			{input: "2QSFzB9ly9neVAlFzR0gNIMr63cGRiVF5OxRjcRHhlY85OrRoM0NzarseyREviggFkNpIonBJbsXaSCsB01nVg=="},
			{input: "da2Pu5AvJtgEK0SoqfoBYJw9zam88iM1PAGg9NixsvYvMdZO2WdR71jNsUoVDq2tS1qPSq3oNHAu6t9I4GEqKw=="},
		},
		"MICROSOFT_AZURE_FUNCTIONS_DOMAIN": {
			{input: "greysteil.azurewebsites.net"},
		},
		"MICROSOFT_AZURE_FUNCTION_KEY": {
			{input: "G0fag/hOCXP6HijGGcpkJqjHzj0JUJVwuMlKisN0GzEBUaV1X9Nypw=="},
			{input: "F7cU6054TW63FzSuVZhvkMRESdoc2frY7wvlO5vwybjFtaKWUUFksA=="},
		},
		"MICROSOFT_AZURE_FUNCTION_KEY_IDENTIFIABLE": {
			{input: "Ye2kNbupxqIvgDhnML1_OffbwlusYh4EZH8Z1nHO9gjIAzFum5njkw=="},
			{input: "lK5jX2d5NshGriQx82EMrIErJ8t5PuQRgjpvGXVcO-lFAzFuSrSj6g=="},
			{input: "jDSuxlIfYaRdcE5f9QVz5-fEvjpcTvnh6MF0H35vZnFNAzFuMLydEA=="},
		},
		"MICROSOFT_AZURE_SEARCH_DOMAIN": {
			{input: "grey-test.search.windows.net"},
		},
		"MICROSOFT_AZURE_SEARCH_KEY": {
			{input: "BA6A9726E62BBFE45CB1090F350D4911"},
		},
		"MIDTRANS_PRODUCTION_SERVER_KEY": {
			// Generated at https://dashboard.midtrans.com/settings/config_info
			{input: "Mid-server-OMFwaEC6_kuXs-GIaNmsrFgf"},
		},
		"MIDTRANS_SANDBOX_SERVER_KEY": {
			// // Generated at https://dashboard.sandbox.midtrans.com/settings/config_info
			{input: "SB-Mid-server-slKFORKs2MHmgxNS6lRKvdVJ"},
		},
		"MYSQL_CONNECTION_URL_WITH_CREDENTIALS": {
			{input: "mysql://user:password@mydomain.com:1234/otherdb?connect_timeout=10"},
			{input: "mysqlx://user:password@mydomain.com:1234/otherdb?connect_timeout=10"},
			{input: "MYSQL://user:password@mydomain.com:1234/otherdb?connect_timeout=10"},
			{input: "MySQL://user:password@mydomain.com:1234"},
			{input: "mysql+srv://user:password@mydomain.com:1234/db"},
			{input: "mysqlx+srv://user:password@mydomain.com:1234/db"},
		},
		"NEW_RELIC_PERSONAL_API_KEY": {
			{input: "NRAK-F0OVS2BZTOLJBPPFGLVEIBONF8N"},
			{input: "NRAK-99CZDP9SFXM1YU52VKQDLYNSWO4"},
		},
		"NEW_RELIC_REST_API_KEY": {
			{input: "NRRA-952f17703e5f6563c96425abe62a8998970ce035e1"},
			{input: "NRRA-5232d25a437b77aa066f0f31840162b47362f3f727"},
		},
		"NEW_RELIC_INSIGHTS_QUERY_KEY": {
			{input: "NRIQ-uo17Z8bTBfiehls4aXjoJGEShGs-m_4y"},
			{input: "NRIQ-ypiYMsTjJKWKTu1isiclJrXRjitnoS8R"},
		},
		"NEW_RELIC_LICENSE_KEY": {
			{input: "8f1a877dba1bb8991cce20808e42d3d2068eNRAL"},
			{input: "3d64162d031f28b5ce5bac8b52db769eFFFFNRAL"},
		},
		"NOTION_INTEGRATION_TOKEN": {
			{input: "secret_MSMhbP0JnfEFNE8woZH34REYy2NaFh6eUsBv5EBLhXm"},
			{
				input:   "token = secret_MSMhbP0JnfEFNE8woZH34REYy2NaFh6eUsBv5EBLhXm",
				matches: []string{"secret_MSMhbP0JnfEFNE8woZH34REYy2NaFh6eUsBv5EBLhXm"},
			},
			{
				input:          "clientSecret := secret_MSMhbP0JnfEFNE8woZH34REYy2NaFh6eUsBv5EBLhXm",
				shouldNotMatch: true,
			},
			{
				input:          "b93ec27e-8e27-41a1-8a29-f2af716937b0:secret_MSMhbP0JnfEFNE8woZH34REYy2NaFh6eUsBv5EBLhXm",
				shouldNotMatch: true,
			},
		},
		"NOTION_OAUTH_CLIENT_SECRET": {
			{
				input:   "clientSecret := secret_MSMhbP0JnfEFNE8woZH34REYy2NaFh6eUsBv5EBLhXm",
				matches: []string{"secret_MSMhbP0JnfEFNE8woZH34REYy2NaFh6eUsBv5EBLhXm"},
			},
			{
				input:   "b93ec27e-8e27-41a1-8a29-f2af716937b0:secret_MSMhbP0JnfEFNE8woZH34REYy2NaFh6eUsBv5EBLhXm",
				matches: []string{"secret_MSMhbP0JnfEFNE8woZH34REYy2NaFh6eUsBv5EBLhXm"},
			},
			{
				input:          "secret_MSMhbP0JnfEFNE8woZH34REYy2NaFh6eUsBv5EBLhXm",
				shouldNotMatch: true,
			},
			{
				input:          "token = secret_MSMhbP0JnfEFNE8woZH34REYy2NaFh6eUsBv5EBLhXm",
				shouldNotMatch: true,
			},
		},
		"NPM_TOKEN": {
			{
				input:   "_authToken = a32ba0a5-a32b-a0a5-a32b-a0a5a32ba0a5",
				matches: []string{"a32ba0a5-a32b-a0a5-a32b-a0a5a32ba0a5"},
			},
			{
				input:   "NPM_TOKEN=a76c9c68-38eb-4b7d-9d22-30fcc40bc384",
				matches: []string{"a76c9c68-38eb-4b7d-9d22-30fcc40bc384"},
			},
			{
				input:   "TRAVIS_NPM_AUTH_TOKEN=\"642a61bb-884c-4f36-aa6c-ed2def6f6e3c\"",
				matches: []string{"642a61bb-884c-4f36-aa6c-ed2def6f6e3c"},
			},
			{
				input:   "TRAVIS_NPM_AUTH_TOKEN   ='0646cf69-265a-49c2-9fd4-324115bd00cd'",
				matches: []string{"0646cf69-265a-49c2-9fd4-324115bd00cd"},
			},
			{
				input:   "travisNpmAuthToken:8575998b-0008-48e7-99b9-b0f799443fda",
				matches: []string{"8575998b-0008-48e7-99b9-b0f799443fda"},
			},
			{
				input:   "travisNpmAuthToken: '7df89499-2a87-4f70-bd15-5d8853e68bd7'",
				matches: []string{"7df89499-2a87-4f70-bd15-5d8853e68bd7"},
			},
			{
				input:   `{"_userName":"User123","_authToken":"fa91777e-0049-467d-b608-5e5e636225c5"}`,
				matches: []string{"fa91777e-0049-467d-b608-5e5e636225c5"},
			},
			{
				input:   "//173.192.225.82:8080/:_authToken=0c561ee7-0821-4659-bfa8-c8c13ce79129",
				matches: []string{"0c561ee7-0821-4659-bfa8-c8c13ce79129"},
			},
		},
		"NPM_TOKEN_V1_PRECISE": {
			{
				input:   "_authToken = a32ba0a5-a32b-a0a5-a32b-a0a5a32ba0a5",
				matches: []string{"a32ba0a5-a32b-a0a5-a32b-a0a5a32ba0a5"},
			},
			{
				input:   "NPM_TOKEN=a76c9c68-38eb-4b7d-9d22-30fcc40bc384",
				matches: []string{"a76c9c68-38eb-4b7d-9d22-30fcc40bc384"},
			},
			{
				input:   "TRAVIS_NPM_AUTH_TOKEN=\"642a61bb-884c-4f36-aa6c-ed2def6f6e3c\"",
				matches: []string{"642a61bb-884c-4f36-aa6c-ed2def6f6e3c"},
			},
			{
				input:   "TRAVIS_NPM_AUTH_TOKEN   ='0646cf69-265a-49c2-9fd4-324115bd00cd'",
				matches: []string{"0646cf69-265a-49c2-9fd4-324115bd00cd"},
			},
			{
				input:   "travisNpmAuthToken:8575998b-0008-48e7-99b9-b0f799443fda",
				matches: []string{"8575998b-0008-48e7-99b9-b0f799443fda"},
			},
			{
				input:   "travisNpmAuthToken: '7df89499-2a87-4f70-bd15-5d8853e68bd7'",
				matches: []string{"7df89499-2a87-4f70-bd15-5d8853e68bd7"},
			},
			{
				input:   `{"_userName":"User123","_authToken":"fa91777e-0049-467d-b608-5e5e636225c5"}`,
				matches: []string{"fa91777e-0049-467d-b608-5e5e636225c5"},
			},
			{
				input:   "//173.192.225.82:8080/:_authToken=0c561ee7-0821-4659-bfa8-c8c13ce79129",
				matches: []string{"0c561ee7-0821-4659-bfa8-c8c13ce79129"},
			},
		},
		"NPM_TOKEN_V2": {
			{
				input:   "_authToken = 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",
				matches: []string{"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"},
			},
			{
				input:   "NPM_TOKEN=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",
				matches: []string{"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"},
			},
			{
				input:   "TRAVIS_NPM_AUTH_TOKEN=\"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\"",
				matches: []string{"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"},
			},
		},
		"NUGET_API_KEY": {
			{input: "oy2cixhwbdh7jy25wunam6t47xalfojeta5bs537enss5u"},
		},
		"OCTOPUS_DEPLOY_API_KEY": {
			{input: "API-F8GGKWLUVBKPAL3PAZF4EAL54H5PAZEW"},
			{input: "API-G5CHAPOWKMPKWX8FTJQHWFLDK"},
		},
		"OCTOPUS_CLOUD_URL": {
			{input: "https://mydomain.octopus.com"},
			{input: "http://mydomain.octopus.app"},
		},
		"OCULUS_VERY_TINY_ENCRYPTED_SESSION": {
			{input: "FRLAeeoKlVsDghtmSBQXtZAZAtQt1IsJCZCAXq33M1AJRHUPhYDCeBjlKtZBzmt8BfFCXgRscc3JL6AZBHy2MKwO1LuR1BiZBZAh00pkCHGCjofaua12SzEcOQJKNh5lEPI612R5xiJ31dZCetxtWTT8VulkNYEskqXqRP1pOZA0PNz9MkYZD"},
			{input: "FRLAeNazBZCHED2saeleoJzZBq8ZB74A9ZAt6noqimSNBt9AwkS06fipoI9zxVV8tuIFeXKP35kZCDKxeJXEIIFZC93BPnMZBT81MZD"},
		},
		"OKTA_API_TOKEN": {
			// Generated at https://dev-44200264-admin.okta.com/admin/access/api/tokens
			{input: "00lAZ5or-oQBaeg-Swt44qs_PVuw_Uq9SzRPk6yAQA"},
		},
		"OKTA_OAUTH_CLIENT_ID": {
			// Generated at https://dev-44200264-admin.okta.com/admin/apps/active
			{input: "0oa3hk3g994anJeHM5d7"},
		},
		"OKTA_OAUTH_CLIENT_SECRET": {
			// Generated at https://dev-44200264-admin.okta.com/admin/apps/active
			{input: "tHW2hdBD3AnzaPxp2b_Z1K37biFgiGyp7-zqDZck"},
		},
		"ONECHRONOS_API_KEY": {
			{input: "cgxap_j40tTrvOI7Euua3P7FX21DSepfOu3FIDbkboQ6TAb18dcb8e"},
			{input: "cgxap_qXCKP0ikR5g3DqWOxmRqNpGoKBAmuQ4aTlU4I5z0afb2c9a3"},
		},
		"ONECHRONOS_EB_API_KEY": {
			{input: "cgxea_l59yn3zUv2vKoSsN61C6JHvRVBbgC4sxD9AT0iYF8bed335f"},
			{input: "cgxea_fbaTUsWszwsVINX9vOlOd1eM9enlSIqMyLpnuEvl1775d3ff"},
		},
		"ONECHRONOS_EB_ENCRYPTION_KEY": {
			{input: "cgxee_ng16eX1pgGYVAbEmwxbcA68p6WPYhuAzsClrIq9ve5f1205a"},
			{input: "cgxee_Fus9e63YlYsfNQHzgYt3bevTVoYBCq2lmDzAqgxn041d9c85"},
		},
		"ONECHRONOS_OAUTH_TOKEN": {
			{input: "cgxoa_V3FZX8U6dSLyao6hflnPaB1o3GyoYSx35O3AyMXz68af2a3c"},
			{input: "cgxoa_BGgTaJHV9FJomD8GFcZtTAXN8DTlI4tRYtsuv1x798a70443"},
		},
		"ONECHRONOS_REFRESH_TOKEN": {
			{input: "cgxre_q4sqOuUaVhpWs0glXcvsBTA1jTj6ha1ZZCDKc4jk34672ece"},
			{input: "cgxre_fi9eHKxAoTgXQ2ogyd6tsFGUjvSzkbjpLJDqxe4z7ae67421"},
		},
		"ONFIDO_LIVE_API_TOKEN": {
			{input: "api_live.x26vzyaRdW2.MLGlTA_pm94nSQXOKBQGHH7wwArs42Mv"},
			{input: "api_live_us.x26vzyaRdW2.MLGlTA_pm94nSQXOKBQGHH7wwArs42Mv"},
			{input: "api_live_ca.x26vzyaRdW2.MLGlTA_pm94nSQXOKBQGHH7wwArs42Mv"},
		},
		"ONFIDO_SANDBOX_API_TOKEN": {
			{input: "api_sandbox.x26vzyaRdW2.MLGlTA_pm94nSQXOKBQGHH7wwArs42Mv"},
			{input: "api_sandbox_us.x26vzyaRdW2.MLGlTA_pm94nSQXOKBQGHH7wwArs42Mv"},
			{input: "api_sandbox_ca.x26vzyaRdW2.MLGlTA_pm94nSQXOKBQGHH7wwArs42Mv"},
		},
		"OPENAI_API_KEY": {
			{input: "sk-72WiFUFdlMZt5lPetkCYkqhPE18dnOKW2pXqX77C"},
			{input: "sk-prefix123-72WiFUFdlMZt5lPetkCYkqhPE18dnOKW2pXqX77C"},
		},
		"OPENAI_API_KEY_V2": {
			{input: "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"},
			{input: "sk-prefix123-72WiFUFdlMZt5lPetkCYT3BlbkFJkqhPE18dnOKW2pXqX77C"},
		},
		"ORACLE_AUTH_TOKEN": {
			{input: "or_1phau_0g);56}l(w3KL0sEcReT"},
		},
		"ORACLE_CLIENT_CREDENTIALS_USERS": {
			{input: "or_1phoa_7Pa7o[_qN}:RPs8ECreT"},
		},

		"ORACLE_SMTP_CREDENTIALS": {
			{input: "or_1phsm_0{SR3>gkd1JP#MSEcrEt"},
		},
		"ORBIT_API_TOKEN": {
			{input: "obu_tgVTIlefcirsN8I3TMyDlb2RBC7AlWvl_xZ3wgnP"},
		},
		"PACKAGE_LOCK_RESOLVED": {
			{
				input:   "  \"resolved\": \"https://registry.yarnpkg.com/@webassemblyjs/wasm-gen/-/wasm-gen-1.7.11.tgz#9bbba942f22375686a6fb759afcd7ac9c45da1a8\",",
				matches: []string{"\"resolved\": \"https://registry.yarnpkg.com"},
			},
			{
				input:   "  \"resolved\": \"https://registry.npmjs.org/@webassemblyjs/wasm-gen/-/wasm-gen-1.7.11.tgz#9bbba942f22375686a6fb759afcd7ac9c45da1a8\",",
				matches: []string{"\"resolved\": \"https://registry.npmjs.org"},
			},
		},
		"PACKAGE_LOCK_INTEGRITY": {
			{
				input:   "  \"integrity\": \"sha512-7pvAdC4B+iKjFFp9Ztj0QgBndJ++qaMeonT185wAqUnhipw8idm9Rv1UMyBuKtYjfl6ORNkgEgcsYLfHX/GpLw==\",",
				matches: []string{"\"integrity\": \"sha512"},
			},
			{
				input:   "  \"integrity\": \"sha1-l6ERlkmyEa0zaR2fn0hqjsn74KM=\",",
				matches: []string{"\"integrity\": \"sha1"},
			},
		},
		"PAYPAL_ACCESS_TOKEN": {
			{input: "A21AAL4bPbkudthMqLyGV0pu1dlwKc1yxeLzux-eT72xP2CYi0_JAGjDxU68Wwk0CH_Yoihd9C6dYZn9jQonaHB0tlYYDWRog"},
		},
		"PAYPAL_CLIENT_ID": {
			{input: "AexEhpDCTP4XCywoWW64W8NOzVYI8TnCR-Azovtn1WsjrmkLSI6VLz_e0GbtQ5oBJNTZlkVGmiOpA6ut"},
		},
		"PAYPAL_CLIENT_SECRET": {
			{input: "EHZyuOP0luhjJ_xXTQ6Yh1JJrsTAz6Ik-Ebf4FP_uDUa3Mb52ZotHeI-0VCs6wSBqBel3UtWizBxoztx"},
		},
		"PERSONA_PRODUCTION_API_KEY": {
			{input: "persona_production_0a7cfff1-f4e7-4e3d-9ae2-11ff6d7f5b4e"},
			{input: "persona_production_691e6aee-dd7a-4cd5-9e91-7729507f1875"},
			{input: "persona_production_1bc08573-c9f2-4e06-94d8-cc375b954300"},
		},
		"PERSONA_SANDBOX_API_KEY": {
			{input: "persona_sandbox_97c35ed2-dab2-41e0-8112-aba83bfbc138"},
			{input: "persona_sandbox_5248ef96-ef05-45e0-b1c5-632ea3473e00"},
			{input: "persona_sandbox_815f98ff-9650-4b95-b8b2-30dffbd087ee"},
			{input: "persona_sandbox_9a5bd5ee-ceaa-43e2-91ba-7cc6be302d91"},
		},

		"PLAID_API_SECRET_KEY": {
			{input: "480ff33af10be535f1bc61109bfa8a"},
		},
		"PLAID_NAME_PRESENCE": {
			{input: "plaid"},
		},
		"PLANETSCALE_SERVICE_TOKEN": {
			// Suffix is composed of only alphanumeric characters
			{
				input:   "7yuwlc37qf15    pscale_tkn_610Cxd3hC2XXk3kzUxU8AJNXbhlJbI1oxDBi3mVjSEE",
				matches: []string{"pscale_tkn_610Cxd3hC2XXk3kzUxU8AJNXbhlJbI1oxDBi3mVjSEE"},
			},
			// Suffix is composed of alphanumeric characters and a dash
			{
				input:   "w9g53eb7r9vt   pscale_tkn_dyT9n-ffEuDJKG4Cou75f2ZrIpDYdVKxqiut4I6kfmI",
				matches: []string{"pscale_tkn_dyT9n-ffEuDJKG4Cou75f2ZrIpDYdVKxqiut4I6kfmI"},
			},
			// Suffix is composed of alphanumeric characters and an underscore
			{
				input:   "3sf00ecis99p   pscale_tkn_BUdvgWSc_UXOpLzjGa6n18vzvuNXxaL0Majs0PEkchk",
				matches: []string{"pscale_tkn_BUdvgWSc_UXOpLzjGa6n18vzvuNXxaL0Majs0PEkchk"},
			},
			// Suffix is composed of alphanumeric characters, an underscore, and a dash
			{
				input:   "4am8t587txhd   pscale_tkn_XXSYFhFvQc5UERgpXSuik_Qych4I4bz2-xV4wJxWEBA",
				matches: []string{"pscale_tkn_XXSYFhFvQc5UERgpXSuik_Qych4I4bz2-xV4wJxWEBA"},
			},
			// Suffix is at shortest possible length, composed of alphanumeric characters, an underscore, a dash
			{
				input:   "inu51xrth562   pscale_tkn_8_FhNexXplqn7FfGKlQNAePgbHebTA-z",
				matches: []string{"pscale_tkn_8_FhNexXplqn7FfGKlQNAePgbHebTA-z"},
			},
			// Suffix is at longest possible length, composed of alphanumeric characters, an underscore, and a dash
			{
				input:   "ywlr3lehx6sv   pscale_tkn_yzK_8KAWNFnkJCpfz7Bqi-S6DSqRep3JniOdt69yGkEuxoplzjga6n18vzvunx_a",
				matches: []string{"pscale_tkn_yzK_8KAWNFnkJCpfz7Bqi-S6DSqRep3JniOdt69yGkEuxoplzjga6n18vzvunx_a"},
			},
		},
		"PLANETSCALE_OAUTH_TOKEN": {
			// Suffix is alphanumeric only
			{input: "pscale_oauth_SEECxd3hC2XXk3kzUxU8AJNXbhlJbI1oxDBi3mVj610"},
			// Suffix has at least one dash
			{input: "pscale_oauth_pLC3TLg3sBf1SftxKCHSmXI7q7aTSHLm2hd-0w1obm0"},
			// Suffix has at least one underscore
			{input: "pscale_oauth_0TyEpWPjgoai6KoJbwTZBlg32wUbhMxzpvuvMS_RRlk"},
			// Suffix is alphanumeric with one dash and one underscore
			{input: "pscale_oauth_8d80h8wStgwhjlOIK_742p1dQ2TePK0kMHYbn-ccRss"},
			// Suffix at shortest length
			{input: "pscale_oauth_8_FNAePgbHebTAhNexXplqn7FfGKlQ-z"},
			// Suffix at longest length
			{input: "pscale_oauth_yzK_8KAWNFnkJCpfz7Bqi-iOdt69yGkEuxoplzjga6n18vzvunx_aS6DSqRep3Jn"},
		},
		"PLANETSCALE_DATABASE_PASSWORD": {
			// Suffix is alphanumeric only, within acceptable range
			{input: "pscale_pw_n8HpoQwX2b6nj1PaQsSz8pAl3nPQyBzPhODHRrZz5JU"},
			// Suffix has at least one dash
			{input: "pscale_pw_PA5SZVbXXD4ZB1xzmWr0JpQhU49FZaqjObY-bXEspMI"},
			// Suffix has at least one underscore
			{input: "pscale_pw_CRfNJ3BT7UWlv1aAWXIOT_kycACRco0EfMiPavowTX8"},
			// Suffix is alphanumeric with one dash and one underscore
			{input: "pscale_pw_vxbZXHCu5qtOKzz-7nBIj9hxecwcgwzkLwjd2_rIL20"},
			// Suffix at shortest length
			{input: "pscale_pw_s-Tf7wGGZ_lmhMwTfpakdf01rOUlQnIY"},
			// Suffix at longest length
			{input: "pscale_pw_bRqdGmpVIoxECgTncBEDo2Q0aWDfp8iYiSSQlxriZoUdkapfTwMhml_ZGGw7fT-s"},
			// Token is set in the context of a config file, like `database/config.yml`
			{
				input:   "password: pscale_pw_gpDA5mcW7l8VYIVfYSxWp5dJpJUBauFssxfAe65FMHA",
				matches: []string{"pscale_pw_gpDA5mcW7l8VYIVfYSxWp5dJpJUBauFssxfAe65FMHA"},
			},
			// Token is set in the context of a connection string
			{
				input:   "server=127.0.0.1;uid=root;pwd=pscale_pw_fAagpYk49fh0rvL-Ag-7J3HMq6oXk7p1ObLDn4PLHO8;database=test",
				matches: []string{"pscale_pw_fAagpYk49fh0rvL-Ag-7J3HMq6oXk7p1ObLDn4PLHO8"},
			},
			// Token is set in the context of a database URL
			{
				input:   "mysql://user:pscale_pw_LON_V3GKJo51APopfONur0CGHKaknNojisLKF8Y0SdM@planetscale.com",
				matches: []string{"pscale_pw_LON_V3GKJo51APopfONur0CGHKaknNojisLKF8Y0SdM"},
			},
		},
		"POSTGRES_CONNECTION_URL_WITH_CREDENTIALS": {
			{input: "postgres://user:password@mydomain.com:1234/otherdb?connect_timeout=10"},
			{input: "postgresql://user:password@mydomain.com:1234/otherdb?connect_timeout=10"},
			{input: "POSTGRES://user:password@mydomain.com:1234/otherdb?connect_timeout=10"},
			{input: "POSTGRES://user:password@mydomain.com:1234"},
		},
		"POSTGRES_CONNECTION_URL_WITH_CREDENTIALS_AS_PARAMS": {
			{input: "postgres://mydomain.com:1234/otherdb?userspec=my:password&connect_timeout=10"},
			{input: "postgresql://user@mydomain.com:1234/otherdb?connect_timeout=10&password=mypass"},
			{input: "POSTGRES://mydb?host=mydomain.com&user=username&password=mypass"},
		},
		"POSTMAN_API_KEY_V2": {
			{input: "PMAK-5daf23cee2fb6b003ce3e1b4-5268d73d7b978d66a5ab6b180e2278e9ea"},
		},
		"POSTMAN_COLLECTION_KEY": {
			{input: "PMAT-01GK3JW4RHXQMGFBAYWM1X91H5"},
			{input: "PMAT-02HB3JX0BJGGSJCYWGRMMW8996"},
			{input: "PMAT-04GK3JY3SN8JCH40BACYGF0QSQ"},
			{input: "PMAT-71FD3JZ2RKMCFC4GYNT2W8RSAA"},
			{input: "PMAT-9UAK3JZS1GMJY29F3EVN1WSD9R"},
		},
		"PREFECT_USER_API_TOKEN": {
			{input: "pcu_4UU28pqnbHZYFqcsbHczEx4fnp9col1x3aYP"},
		},
		"PREFECT_SERVER_API_TOKEN": {
			{input: "pcs_xDuY3SPgoHfzoGO3YreaXKzLBwkNmX1qEhwH"},
		},
		"PROCTORIO_REGISTRATION_KEY": {
			{input: "PRK4c96f420"},
			{input: "PRK54b9a45a"},
			{input: "PRKa2c08c4b"},
		},
		"PROCTORIO_CONSUMER_KEY": {
			{input: "PCK2d71dfaa9cd841e1808be03b81de0107"},
			{input: "PCK9d6be2665e9c4e7e859e843919636539"},
			{input: "PCKe16acdff7afe49248aaf3f0987af4955"},
		},
		"PROCTORIO_SECRET_KEY": {
			{input: "PSKfb3517151a2143f2bdc544ab00ff7663"},
			{input: "PSK15f87bd8a4304b24af4695afc3438943"},
			{input: "PSK8df5b03f72f64bd8841c90baa5cf8ea5"},
		},
		"PROCTORIO_SECRET_KEY_V2": {
			{input: "PSK48a3c79534024c93b37e010cdcfaf1c45cdf38f954334b439042fcbbb6842a536bd90c042b6140d1868fc04be9dc141c864dfd5957d540c18efc48149dbf6951b48f0a8685e54c05904932e197788a3c66d67769c162482c8528f95b169d5642e0e87f8d2ced4e3f89c915fefe694c739c16853f046c46e6b5212552f5ade6f9"},
		},
		"PROCTORIO_LINKAGE_KEY": {
			{input: "PLK4c887b712b7840dc9b72c5f003008a95"},
			{input: "PLK82f2828868374865b095378ed087863c"},
			{input: "PLK1ce0e6a60a97434a957fa0ec5e560cdb"},
		},
		"PULUMI_ACCESS_TOKEN": {
			{input: "pul-2b570c803e6199f3be71e94aaff821552d53f05e"},
		},
		"PYPI_API_TOKEN": {
			// Generated from https://pypi.org/manage/account/token/
			{input: "pypi-AgEIcHlwaS5vcmcCJDgzMDAxYWUwLTlmNmUtNDg5Yi1iYjk3LWU3MWVmZjViZTMxYQACJXsicGVybWlzc2lvbnMiOiAidXNlciIsICJ2ZXJzaW9uIjogMX0AAAYgaHD8eyuRtJGxH_MM0MLs7mZnbMD9wHH8Y-peY8TNBgY"},
		},
		"RAILWAY_POSTGRES_CONNECTION_URL": {
			{input: "postgresql://postgres:XzcaKjALdMdhEP7sx18S@containers-us-west-19.railway.app:6937/railway"},
			{input: "postgres://postgres:XzcaKjALdMdhEP7sx18S@containers.railway.app:6937/railway"},
		},
		"RAZORPAY_LIVE_API_KEY_ID": {
			{input: "rzp_live_AsnKdS324dsf32"},
		},
		"RAZORPAY_LIVE_API_KEY_SECRET": {
			{input: "wjUOB2CXzR9cnMCFmCglqfQM"},
		},
		"RAZORPAY_TEST_API_KEY_ID": {
			{input: "rzp_test_AsnKdS324dsf32"},
		},
		"RAZORPAY_TEST_API_KEY_SECRET": {
			{input: "FMYNq2BvVVpQk9zc72d0JAby"},
		},
		"READMEIO_API_ACCESS_TOKEN": {
			{input: "rdme_xn8s9hb7bde0a801f94b8794bd2b31a11018bed26f56b46a281927bb0231f411dc3796"},
			{input: "rdme_xn8s9h8bbc14db09db8ad9b5ac17e8140742984dd2f80c61385cb8d2ff682f38784279"},
			{input: "rdme_xn8s9h583748db7877c402578ed6ba0b8ea212b65ff62f6edebf4a89e63d0abc8c1609"},
		},
		"REDIRECT_PIZZA_API_TOKEN": {
			// Generated knowing the pattern is rpa_<64-char-random-lowercase-alphanumeric-string>
			{input: "rpa_cbm2g6x2o4mnp36p451r3e0gbgnbk9hn1x7u1sd6hatz3c67knnkfk7j6qfat57w"},
			{input: "rpa_icenvf1xg00rl6knvplg4vnnimbixrfzg1s2itqzrjv4xl17p5i4jbkh6wmjttk3"},
			{input: "rpa_nzb3g74abywjo9ly6fy40yf8fd473fhj4tpnqoi6vdoevd9ocswzq2y1tp4gam1r"},
			{input: "rpa_1n467qp5bziw817cjmr3digm8imcbe9cxs3w2luy80oe28dpet9zv00wzx1jn7b9"},
			{input: "rpa_nbrjkvhu4qiaioawhrkk8ruegarx2dkcr7edb45gkms1psoitgh82s8xy0hcrgzs"},
		},
		"REVENUECAT_SECRET_KEY": {
			// Generated from https://app.revenuecat.com/apps/<app_id>/authentication
			{input: "sk_vdSDPHTtNyadiWPagpVYHPdPEoXou"},
		},
		"ROOTLY_API_KEY": {
			{input: "rootly_f346432b03e578be7db4afcb54a59da8337b88be5eff2ea22a68d75128f536af"},
			{input: "rootly_f85322261a3d4a57ad51d7efcd7518976b5120014c4d1c7710856721af549e3f"},
			{input: "rootly_7dfa832040c0793e2fa1959348aabaf8405151f25b0ba9e59a3f9f14d743a286"},
			{input: "rootly_0c36cb2a5673ffaf87618f4e1c743bf4ab70c952457669a94cb2173bad9f2178"},
			{input: "rootly_1c2c4f1b0b0a14a64d395e3524778d43891c2e7232091d3f3a752dfdf3427ab8"},
			{input: "rootly_465d629bb77fd012587023dc964ce50e28ec4b20a419788991b37cb918449152"},
		},
		"RUBYGEMS_API_KEY": {
			// Generated from https://rubygems.org/profile/api_keys
			{input: "rubygems_3dd70baa98a1ca590628b2eb1dbcb99a552e2c7391f56091"},
		},
		"SAMSARA_OAUTH2_ACCESS_TOKEN": {
			{input: "gzUdQrDW:4:my_token_string"},
			{input: "gzUdQrDW:1234:another_token_string"},
			{input: "gzUdQrDW:5555555555:1a2b3c4d5e"},
			{input: "gzUdQrDW:0:another_token_string"},
		},
		"SAMSARA_API_ACCESS_TOKEN": {
			{input: "samsara_api_01nasldfknasldfnlsakdnflksadnf"},
			{input: "samsara_api_111111111111111111111111111111"},
			{input: "samsara_api_bof97AO53babf01mnqpAb901kbdlpm"},
		},
		"SECRET_SCANNING_SAMPLE_TOKEN": {
			{input: "secret_scanning_ab85fc6f8d7638cf1c11da812da308d43_aA9Zz"},
		},
		"SEGMENT_CONFIG_API_TOKEN": {
			{input: "MNSZSRcWaY_rrgfqzLEADbdgEQP2paBm1p2YhCsPMXA.RoOkR-EaKAy416F5iAaCBqIJLf14U5mMqFQaLkTglb0"},
		},
		"SEGMENT_PUBLIC_API_TOKEN": {
			{input: "sgp_iJxyu4JkSaVUS1EVBmaok0YAl56uLr3ipY7BiJxyu4JkSaVUS1EVBmaok0YAl56u"},
		},
		"SENDGRID_API_KEY": {
			// Generated from https://app.sendgrid.com/settings/api_keys. Includes full, restricted and billing tokens
			{input: "SG.LGS6i3i1RnijKO2MvTm9sg.99e5Sv0_K0-qehN9MW0kkVcnMGMvsK6TfgTiWUlUgnc"},
			{input: "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"},
			{input: "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"},
		},
		"SENDINBLUE_API_KEY": {
			{input: "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"},
			{input: "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"},
		},
		"SENDINBLUE_SMTP_KEY": {
			{input: "xsmtpsib-d7ea52cc47380ae13b09f3b5f7bd7495fc59e0f27cff6683a81033368cc7beb3-bDswMxHdXROJIGyj"},
			{input: "xsmtpsib-68f4cff60c9712e1ccca66b55845f24e1c265a6854a2ec362cad6bee90edfad9-4yS6a5Z0HzvhRXAG"},
		},
		"SENTRY_AUTH_TOKEN": {
			{input: "ea9ffaf56b4f43d394507a9048d2cf7b61ef10f63eab4215b822d68068bc36f3"},
			{input: "53510a8ce05849d6af10de1d588b2ae8ea9ff11de9b444ed8cc923fa3806da0f"},
		},
		"SENTRY_NAME_PRESENCE": {
			{input: "sentry"},
			{input: "Sentry"},
			{input: "SentryAccessToken", matches: []string{"Sentry"}},
			{input: "MySentryAccessToken", matches: []string{"Sentry"}},
		},
		"SHIPPO_LIVE_API_TOKEN": {
			// Generated at https://app.goshippo.com/settings/api/
			{input: "shippo_live_032a063af08006e021c1cfbec690e16a1116c9d3"},
		},
		"SHIPPO_TEST_API_TOKEN": {
			// Generated at https://app.goshippo.com/settings/api/
			{input: "shippo_test_d83e049e5be4203609b203477d375f2e1736359a"},
		},
		"SHOPIFY_APP_SHARED_SECRET": {
			// shpss_[a-fA-F0-9]{32,64}
			{input: "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"},
		},
		"SHOPIFY_ACCESS_TOKEN": {
			// shpat_[a-fA-F0-9]{32,64}
			{input: "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"},
		},
		"SHOPIFY_CUSTOM_APP_ACCESS_TOKEN": {
			// shpca_[a-fA-F0-9]{32,64}"
			{input: "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"},
		},
		"SHOPIFY_PRIVATE_APP_ACCESS_TOKEN": {
			// shppa_[a-fA-F0-9]{32,64}
			{input: "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"},
		},
		"SHOPIFY_MERCHANT_TOKEN": {
			{input: "atkn_e28f1e37c8d0482fad29c576a7eb2e34e5fc9906663d4dd425153507f77dac0d"},
			{input: "atkn_7284a5816ee9cc9a38a9eb00b36526283dc677f6a93879f493af3785eb69de82"},
		},
		"SHOPIFY_APP_CLIENT_CREDENTIALS": {
			{input: "ptkn_e28f1e37c8d0482fad29c576a7eb2e34e5fc9906663d4dd425153507f77dac0d"},
			{input: "ptkn_7284a5816ee9cc9a38a9eb00b36526283dc677f6a93879f493af3785eb69de82"},
		},
		"SHOPIFY_APP_CLIENT_SECRET": {
			{input: "ztkn_e28f1e37c8d0482fad29c576a7eb2e34e5fc9906663d4dd425153507f77dac0d"},
			{input: "ztkn_7284a5816ee9cc9a38a9eb00b36526283dc677f6a93879f493af3785eb69de82"},
		},
		"SHOPIFY_PARTNER_API_TOKEN": {
			{input: "prtapi_e28f1e37c8d0482fad29c576a7eb2e34e5fc9906663d4dd425153507f77dac0d"},
			{input: "prtapi_7284a5816ee9cc9a38a9eb00b36526283dc677f6a93879f493af3785eb69de82"},
		},
		"SHOPIFY_MARKETPLACE_TOKEN": {
			{input: "shpmkt_29aaaab5_fd01b459c8f9143955609970eac99d26"},
			{input: "shpmkt_55a06985_8bc10cb547ce9c23c635734a1c205d96"},
			{input: "shpmkt_6524894c_d61d63b0393474be008ddc985e0f8e3c"},
			{input: "shpmkt_46a8b309_220d26cdfe16aad0365da6ed5573b458"},
			{input: "shpmkt_c7190fe6_a5f047f4fb9b9919c9116df6a177fb27"},
		},
		"SIEMENS_CODE_STAGING_TOKEN": {
			{input: "CSC-STAGE-CrkTzHfh-sQxQ2RcT4oX"},
			{input: "CSC-STAGE-NVMheeyJdvPiQZ8pMg3s"},
		},
		"SIEMENS_CODE_TOKEN": {
			{input: "CSC-AzXYFpG_ktmCVvZzajAy"},
			{input: "CSC--u3fZDAQmd7J5RdtzSHV"},
			{input: "CSC-na6MRhxZ1zp-Z6bTxzTP"},
		},
		"SLACK": {
			// xoxb-([0-9]{7,})-([A-Za-z0-9]{14,})
			{input: "xoxb-1368424119-g5tqnFIgqFkOo6s2eb9K6xwZ"},
			// xoxp-([0-9]{7,})-([0-9]{7,})-([0-9]{7,})-([0-9a-f]{12,})
			{input: "xoxp-301821206114-402356108740-432597256163-1031547d0e249dfc74ff395f320a66c8"},
			// xoxs-([0-9]{7,})-([0-9]{7,})-([0-9]{7,})-([0-9a-f]{7,})
			{input: "xoxs-67637314004-57593728235-592547223719-58fc5f56ea"},
			// xoxa-([0-9]{7,})-([0-9]{7,})-([0-9]{7,})-([0-9a-f]{7,})
			{input: "xoxa-19222199748-620163919616-382139166278-a7bb60962ef837d0354365c00664c9bb"},
			// xoxa-2-([0-9]{7,})-([0-9]{7,})-([0-9]{7,})-([0-9a-f]{7,})
			{input: "xoxa-2-29222199748-320163919616-486139166278-e7bb60862ee837d0354365c00664c9bb"},
			// xoxr-([0-9]{7,})-([0-9]{7,})-([0-9]{7,})-([0-9a-f]{7,})
			{input: "xoxr-601821206113-902356208740-632297256163-3031547d0f249dfc74fe395f320a66c8"},
			// xoxo-([0-9]{7,})-([A-Za-z0-9]{14,})
			{input: "xoxo-21575374614-66DKNARdweYlzrnHhiKtgBpH"},
			// xoxb-([0-9]{7,})-([0-9]{7,})-([A-Za-z0-9]{14,})
			{input: "xoxb-369235392313-402135264013-A74d96kXs9Tuep59PZSWNkdE"},
			{input: "xoxp-0482219004-1514018645-843348003612-aabbcc"},
			{input: "xoxp-0222210004-4014586151-368430012348-aa1234bb213cc"},
			{input: "xoxb-0482219004-1514018645-84aababacasdfasdfasd"},
			{input: "xoxb-0482219004-11234AASDAB2314kdf"},
		},
		"SLACK_OPAQUE": {
			{input: "xoxe.xoxb-1-111111111111LTEyMzQ1NjctMTIzNDU2Ny0xMjM0NTY3ODkwLTNjN2J111111WUyMGRl1232NDQwMDg0YTUyYWM5Y2RjZ11111RlYjkxYjQ5OThhYmQ1ODZjOGEz111111"},
		},
		"SLACK_APP_LEVEL": {
			{input: "xapp-1-A01225LDDDD-1670597111111-b75fdf8f238fe0d2bfa6022a883ed09d00000000001111111111111111111111"},
			{input: "xapp-1-D01242KFFFF-1670597222222-a43edf8f138de0d2bfed011a653ed09d11111111110000000000000000000000"},
		},
		"SLACK_WEBHOOK": {
			{input: "https://hooks.slack.com/services/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"},
			{input: "https://hooks.slack.com/services/T0hjvf1fg/C0VSV3MQT876/80qTgG1wLSFiyAxXCNET30zx"},
			{input: "https://hooks.slack.com/services/T0HJVF1FGBB9/C0VSV3MQT/80qTgG1wLSFiyAxXCNET30zx"},
		},
		"SLACK_WORKFLOW_WEBHOOK": {
			{input: "https://hooks.slack.com/workflows/TABCDE123/A00000001/283356900064493550/eCwHs0XriFNUHAqG6SxEiYad"},
			{input: "https://hooks.slack.com/workflows/TABCDE1234/A00000002/283356900064493551/eCwHs0XriFNUHAqG6SxEiYdd"},
			{input: "https://hooks.slack.com/workflows/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"},
			{input: "https://hooks.slack.com/workflows/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"},
		},
		"SONARQUBE_GLOBAL_ANALYSIS_TOKEN": {
			// See https://github.com/SonarSource/sonarqube/blob/09e15e545/server/sonar-webserver-auth/src/main/java/org/sonar/server/usertoken/TokenGeneratorImpl.java
			{input: "sqa_0172c821af007e813158d6f051f9a716cd3dbdaf"},
		},
		"SONARQUBE_PROJECT_ANALYSIS_TOKEN": {
			// See https://github.com/SonarSource/sonarqube/blob/09e15e545/server/sonar-webserver-auth/src/main/java/org/sonar/server/usertoken/TokenGeneratorImpl.java
			{input: "sqp_0172c821af007e813158d6f051f9a716cd3dbdaf"},
		},
		"SONARQUBE_USER_TOKEN": {
			// See https://github.com/SonarSource/sonarqube/blob/09e15e545/server/sonar-webserver-auth/src/main/java/org/sonar/server/usertoken/TokenGeneratorImpl.java
			{input: "squ_0172c821af007e813158d6f051f9a716cd3dbdaf"},
			// Disallow matches that come from badges (these are not real user tokens, they're a special case that is safer)
			{
				input:          "api/project_badges/measure?project=demo&metric=coverage&token=squ_0172c821af007e813158d6f051f9a716cd3dbdaf",
				shouldNotMatch: true,
			},
			{
				input:          "api/project_badges/measure?token=squ_0172c821af007e813158d6f051f9a716cd3dbdaf&project=demo&metric=coverage",
				shouldNotMatch: true,
			},
		},
		"SQUARE_ACCESS_TOKEN": {
			// Generated from https://developer.squareup.com/. Includes sandbox and production personal access tokens and an OAuth token
			{input: "EAAAEPzpcX2-iBOcRMTS18_ItnYHTSYXBqutZwQTvvTDeQuiYWdvbPg0XPELiOrX"},
			{input: "EAAAEf0zyo_99yOF7S7PGqc9ddDkRc42dwnOzh3waTUB3Go35UtTZKufw4Q9ODSO"},
			{input: "EAAAFNqFp03qKTbApfbyeUdMsjUkYNecWb7bzCAFryJ2HITNAL1GeZY3vSO3hSQq"},
		},
		"SQUARE_SANDBOX_APPLICATION_SECRET": {
			// Generated from https://developer.squareup.com/. Includes sandbox and production personal access tokens and an OAuth token
			{input: "sandbox-sq0csb-w3DIRroaDaBVGIUKWMSJRR9y30CSow2panA6UVZsZx4"},
			{input: "sq0csb-w3DIRroaDaBVGIUKWMSJRR9y30CSow2panA6UVZsZx4"},
		},
		"SQUARE_PRODUCTION_APPLICATION_SECRET": {
			// Generated from https://developer.squareup.com/. Includes sandbox and production personal access tokens and an OAuth token
			{input: "sq0csp-h_MN0Eb-y0WgtDiYY2tl0E62Nl_G8Dqd9Gz53RO-RaE"},
		},
		"SQUARE_LEGACY_SANDBOX_ACCESS_TOKEN": {
			{input: "sq0atb-nn_yQbQgZaA3VhFEykuYla"},
			{input: "sandbox-sq0atb-nn_yQbQgZaA3VhFEykuYla"},
		},
		"SQUARE_LEGACY_PRODUCTION_ACCESS_TOKEN": {
			{input: "sq0atp-8s3CbjRnuPx9lsptHJ9QYa"},
		},
		"SSLMATE_API_KEY": {
			{input: "api_key 1_sgToaN43gfSQdS20iChs"},
			{input: "api_key 20032_68b329da9893e34099c7d8ad5cb9c940"},
			{input: "api_key k521_9bb96b0d7ef9819378bc4928bf603224"},
			{input: "api_key k2109700915100_bc5T6Zbfv5oOwrwb3qyn"},
		},
		"SSLMATE2_API_KEY": {
			{input: "api_key = \"1_sgToaN43gfSQdS20iChs\""},
			{input: "api_key = \"20032_68b329da9893e34099c7d8ad5cb9c940\""},
			{input: "api_key = \"k521_9bb96b0d7ef9819378bc4928bf603224\""},
			{input: "api_key = \"k2109700915100_bc5T6Zbfv5oOwrwb3qyn\""},
		},
		"SSLMATE_CLUSTER_SECRET": {
			{input: "secret = \"naclsecretbox:ZmaValAsfTebxCV-yCVD3BGidJWdDjAfzGz3Y8VNVN4\""},
			{input: "secret = \"naclsecretbox:dfpiCL9KXnpVPI0Jw821uSdnGJGL-oC6v3ELbueLKso\""},
			{input: "secret = \"naclsecretbox:9-xgkdUsn4Ug4_3xOL6xsOI61jUSExdwZ2dfNmjm-7o\""},
		},
		"STACKHAWK_API_KEY": {
			{input: "hawk.roK6wT3uSKnOkfMkMq1j.jLwoYSLaZtnJPqSKyZZZ"},
		},
		"STREAM_API_SECRET": {
			// Generated at https://dashboard.getstream.io/dashboard/v2
			{input: "bbxe7exty8wuyyqdvamnusjj2garqaf9vs3vzcs3cjvvwfdbx65sxax5ffyww9pc"},
		},
		"STRIPE_LIVE_API_SECRET_KEY": {
			{input: "sk_live_BQokikJOvBiI2HlWgH4olfQ2"},
			{input: "sys_live_AUokikJOvBiI2HlWgH4olfQ2J7fe6AnvRf"},
		},
		"STRIPE_TEST_API_SECRET_KEY": {
			{input: "sk_test_BQokikJOvBiI2HlWgH4olfQ2"},
			{input: "sys_test_AUokikJOvBiI2HlWgH4olfQ2J7fe6AnvRf"},
		},
		"STRIPE_LIVE_API_RESTRICTED_KEY": {
			{input: "rk_live_BQokikJOvBiI2HlWgH4olfQ2"},
		},
		"STRIPE_TEST_API_RESTRICTED_KEY": {
			{input: "rk_test_BQokikJOvBiI2HlWgH4olfQ2"},
		},
		"STRIPE_LEGACY_API_SECRET_KEY": {
			{input: "sk_BQokikJOvBiI2HlWgH4olfQ2olfQ2"},
			{input: "sys_AUokikJOvBiI2HlWgH4olfQ2J7fe"},
		},
		"STRIPE_WEBHOOK_SIGNING_SECRET": {
			{input: "whsec_zfK8msg9T76JIGReYJiESWkYK4nUhwCt"},
			{input: "whsec_7Bi9ZVEYTQCnQUVwqTC4tVtli9I8HdLf"},
		},
		"SUPABASE_NAME_PRESENCE": {
			{input: "Supabase"},
			{input: "supabase"},
		},
		"TABLEAU_PERSONAL_ACCESS_TOKEN": {
			{input: "vNAbT95fRHq/KiD8onMqWQ==:D3qp6TJuF6DZXDaTYcYXBGHTSKPiGl0Q"},
			{input: "yxFHI4r/TmqLfKLYqYdo/g==:Z3pRQVzuFCzW0BXiBNkBLYGWIcnOzwWT"},
		},
		"TELEGRAM_BOT_TOKEN": {
			{input: "1217922102:AAHiIKy8gXqS-1ypbPxRbmOadGDdBOxbQxY"},
			{
				input:   "https://api.telegram.org/bot123456:AAC-DEF1234ghIkl-zyx57W2v1u123ew11/getMe",
				matches: []string{"123456:AAC-DEF1234ghIkl-zyx57W2v1u123ew11"},
			},
		},
		"TELNYX_API_V2_KEY": {
			{input: "KEY0174227C1D16D1B180A8FF742AD37F70_1bA4vlJKHpZcJGaSXaadFu"},
			{input: "KEY016FC40155D65CA04656136B3882D9B0_XuyncNBL9z7guFoNkQMez9"},
			{input: "KEY0180AA74D03626FE3FE4B92C29098444_RlA0xquqwiXXnD4Y6g3xxo"},
			{input: "KEY0180AA7490108B5BCB8A2DD35DF19C20_SSBEbmbrK816h0qJ8I2maL"},
			{input: "KEY0180AA745252BC766431DF53FC8633E7_ECzzLmwZblx1vmMlboAO7b"},
		},
		"TENCENT_CLOUD_SECRET_ID": {
			{input: "AKIDc4Q483nNnMtKcnwtpcq882jusxX8tAYQ"},
		},
		"TENCENT_WECHAT_API_APP_ID": {
			{input: "wxb4ba3c02aa476ea1"},
			{input: "wx426b3015555a46be"},
			{input: "wx40d1a3b4f4d36e6e"},
			{input: "wxd5609f7b5b4dd051"},
			{input: "wxc0b45b17242219f1"},
		},
		"TENCENT_WECHAT_API_APP_SECRET": {
			{input: "1f2d63d8f7a3a3a2690d569f1103e5aa"},
		},
		"TERRAFORM_CLOUD_ENTERPRISE_TOKEN": {
			{input: "msOTtGD6Y4MCaw.atlasv1.6xZy3T1Uz2BvxrTSnvzHiB0ciotRnSuZsbvCQZJH5616yXueGTuNoz1azK2PNeR8SR8"},
			{input: "5q7mW6RCzQCZCA.atlasv1.OatUvEjRuutDGZzOSwDlyDLhVSPotnwME6jDygx4vLluLvs5fBqKo1TocMoIfWRZkVw"},
			{input: "xNBffcVGD52J3A.atlasv1.Ds9J8WgjDWdFJ4Hzb6fVc626ImglR6DJTAJdbGy7Eegt5yzmwsGubRME3Fz4poixw4Y"},
			{input: "O7KPQgaswBFb6w.atlasv1.F9AxP2yPqxiykr0tyAzeb8gQg5Pt060Xtr3bbzCAuy2l8cQGLBraPevMeODR0Qul8hc"},
			{input: "23iqZiyWydpG1A.atlasv1.VlgJbox4aJDJ58r7H5Y4dykrS4C6e4PNDZXju5DvljCVXfQPiNYNzGAMbgq72UFxfG0"},
		},
		"THUNDERSTORE_IO_API_TOKEN": {
			{input: "tss_IGfnDvYuDYNeR4UVOdmL2UttL2SonW0jcETs"},
		},
		"TWILIO_ACCOUNT_SID": {
			// Twilio account SID
			{input: "AC02d9c4d2a4c5b509c65eb13ef59015d2"},
		},
		"TWILIO_API_KEY_SID": {
			// Twilio auth token
			{input: "SKc15b1dad6587f721ac21d44c1ffffc26"},
		},
		"TYPEFORM_PERSONAL_ACCESS_TOKEN": {
			{input: "tfp_Fbzs4w9UnM1nmVGKoQaBpq8NHxEhGoYCY5WXhG5UZdck_eoMLSNTXzmFH"},
		},
		"VALOUR_ACCESS_TOKEN": {
			{input: "val-6A65B38E-419B-4155-B15C-254F750D28AE"},
			{input: "val-6a65b38e-419b-4155-b15c-254f750d28af"},
		},
		"VAULT_BATCH_TOKEN": {
			{input: "b.AAAAAQJEH5VXjfjUESCwySTKk2MS1MGVNc9oU-N2EyoLKVo9SYa-NnOWAXloYfrlO45UWC3R1PC5ZShl3JdmRJ0264julNnlBduSNXJkYjgCQsFQwXTKHcjhqdNsmJNMWiPaHPn5NLSpNQVtzAxfHADt4r9rmX-UEG5seOWbmK_Z5WwS_4a8-wcVPB7FpOGzfBydP7yMxHu-3H1TWyQvYVr28XUfYxcBbdlzxhJn0yqkWItgmZ25xEOp7SW7Pg4tYB7AXfk"},
			{
				input:          "hvb.AAAAAQJEH5VXjfjUESCwySTKk2MS1MGVNc9oU-N2EyoLKVo9SYa-NnOWAXloYfrlO45UWC3R1PC5ZShl3JdmRJ0264julNnlBduSNXJkYjgCQsFQwXTKHcjhqdNsmJNMWiPaHPn5NLSpNQVtzAxfHADt4r9rmX-UEG5seOWbmK_Z5WwS_4a8-wcVPB7FpOGzfBydP7yMxHu-3H1TWyQvYVr28XUfYxcBbdlzxhJn0yqkWItgmZ25xEOp7SW7Pg4tYB7AXfk",
				shouldNotMatch: true,
			},
		},
		"VAULT_BATCH_TOKEN_IDENTIFIABLE": {
			{input: "hvb.AAAAAQJEH5VXjfjUESCwySTKk2MS1MGVNc9oU-N2EyoLKVo9SYa-NnOWAXloYfrlO45UWC3R1PC5ZShl3JdmRJ0264julNnlBduSNXJkYjgCQsFQwXTKHcjhqdNsmJNMWiPaHPn5NLSpNQVtzAxfHADt4r9rmX-UEG5seOWbmK_Z5WwS_4a8-wcVPB7FpOGzfBydP7yMxHu-3H1TWyQvYVr28XUfYxcBbdlzxhJn0yqkWItgmZ25xEOp7SW7Pg4tYB7AXfk"},
		},
		"VAULT_SERVICE_TOKEN": {
			{input: "s.Alh1jtrq6gsNyNWvGViHYpiu"},
			{
				input:          "s.startDKGWithParticipants(s.nodeAccounts)",
				shouldNotMatch: true,
			},
			{
				input:          "$2b$08$cytKEpFUcIjvaa9tnQtAAe74/N.s.2D9jFVtLnUHcgaZ2xJ1TnnQC",
				shouldNotMatch: true,
			},
			{
				input:          "hvs.Alh1jtrq6gsNyNWvGViHYpiu",
				shouldNotMatch: true,
			},
		},
		"VAULT_SERVICE_TOKEN_IDENTIFIABLE": {
			{input: "hvs.Alh1jtrq6gsNyNWvGViHYpiu-Wxi3xp7yPa1Z1RWv1P9UyHVGh4KHGh2cy5GUmYzTzdJOWhIZGFNSm5jdTBsSVNFSTk"},
		},
		"VAULT_ROOT_SERVICE_TOKEN": {
			{input: "hvs.Alh1jtrq6gsNyNWvGViHYpiu"},
			{
				input:          "hvs.startDKGWithParticipants(hvs.nodeAccounts)",
				shouldNotMatch: true,
			},
			{
				input:          "$2b$08$cytKEpFUcIjvaa9tnQtAAe74/N.hvs.2D9jFVtLnUHcgaZ2xJ1TnnQC",
				shouldNotMatch: true,
			},
			{
				input:          "hvs.Alh1jtrq6gsNyNWvGViHYpiu-Wxi3xp7yPa1Z1RWv1P9UyHVGh4KHGh2cy5GUmYzTzdJOWhIZGFNSm5jdTBsSVNFSTk",
				shouldNotMatch: true,
			},
		},
		"WISEFLOW_API_KEY": {
			{input: "wfs_1_xom8TQ0Gs5mVnFp3zitsEUBTXxR2OOFA0qymQZ"},
			{input: "wfs_1_hX06GnTd8Ngk0XnakT3vjGnSvyeuuO9w0sQvTL"},
		},
		"WAKATIME_API_KEY": {
			{input: "waka_7df89f5d-5c5c-4b8c-9fe5-1587083fe411"},
			{input: "waka_c697542b-667c-4a86-800a-2bc01bf4ddaa"},
		},
		"WAKATIME_APP_SECRET": {
			{input: "waka_sec_yiRZoTuXevBbcI03A6cXGv1eDl4u85kCCp0XRXwte3ccDXLCOJCTsd06Vdm68TIG9JermGLW2RWxbyIU"},
			{input: "waka_sec_6OQvvQ63Lo42EzbFMY94o8D0WRVGIznVGglhuK3favvmMDdNfnH7YPoH349OuKIzgtutnHIdhcLDYavO"},
		},
		"WAKATIME_OAUTH_ACCESS_TOKEN": {
			{input: "waka_tok_eZ9kI3tQlYVvYSJOAjoI5n3PpyG69HQl91TZKFjSdb0X0XXgY7dahXiPpAhYL2kNxqDBzHuHNuzCPr5d"},
			{input: "waka_tok_7TJvOvyP2Me28UYEZkYfNbWpl8dyGboMU5yLgslwHDhOoFqSs79m8AHCxPc55Ge9My9hrT8cQ8jezzK2"},
		},
		"WAKATIME_OAUTH_REFRESH_TOKEN": {
			{input: "waka_ref_3LICH9YivbaqUHUpxhwuBtShFrbwXMoXb8zmpyWxqOPYQmJIsKLzxXFdXubi2iwUW0tnaLHE1axIpY8z"},
			{input: "waka_ref_2grhX55MDAIBOQ7dzzGzDQ7zmCezxwGHTQdyzhLsIZc3ue88HfGXJ02Cq69kWlApZ9QHB0NJbvOQQfHx"},
		},
		"WORKATO_DEVELOPER_API_TOKEN_EU": {
			{input: "wrkaeu-eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJzdWIiOiI0NzcwZjU1Ny1mNzM2LTQxNDEtYWMzMS0wZTc5OWRhNDBjYjciLCJqdGkiOiIwOGUzYTFlZS0xN2E4LTRiYTItYWNjZi01MWQ5MGEwODE4NjciLCJleHAiOjE3MDU0ODQ4MjR9.IIq-HouZvDIYaF1w0NeZeNgC0LvxLpwDMlcasTvrXZCKr8rOSkAt6qUifpwOz6nckNfl4tcttnQTMUJyNaLz5O42BqiHmMZ_gtHGHqsWVz8gAsbpUxAyrkjy2vbLC-4fJYZQf85MQr58wMnrY9Qzqn7PA83wJto7CMpAfMZegUsUY5_jDQnkeZHryxaA-zqjQBdxYJAj6AEvMY3lJfCMz2m3oN3vz7JbIshyUCWNr4xpHMp_H4hBRsVgSkLi3_W4rhZSFwUnXB7S9_ajHcsU9WhjrgwvJSIgqN614JnuNr3G4UCVE0Z0LBTvn7ctL0CAjoFE08T7A_7IhU5gV8zVljPHfccFO6aspPD0_A04sd2pTwIE7sNnHL5PIIxhU_MiBJG0C049zyc5iBF1jTV1UGZ-a8xx3SLMLRCmguSWCAV7FBW4pcdKMnjmuMPz6PwHXtTACXcDgUQTl_YaC9GebXQ0wEL_o9hJ9QIj_CZyze_2fjqYNFk1JaGB6amRe5cMMY74VtUvEer8nH7e7satEcVuaH1f7voKtQWbMPBdhjy5K7obHya9PoVu2VO0SeFatPs14dwULGywfb8d-ktlvZeYHJSvK4GVhZt2apunAv6qCltXkS2By9EWiHAIQenRbGZRu7OwohYe_JUk6kLm5LwKWkkWQKkbt_Kg88cPEGg"},
		},
		"WORKATO_DEVELOPER_API_TOKEN_JP": {
			{input: "wrkajp-eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJzdWIiOiI0NzcwZjU1Ny1mNzM2LTQxNDEtYWMzMS0wZTc5OWRhNDBjYjciLCJqdGkiOiJkNjYwYzBiMi0wYzU5LTRkYmUtYmNkMS00N2Y3YTk0NDFmNWQiLCJleHAiOjE3MDU0ODQ4OTV9.gwtAsnO-J-CKuGg1-xthEIRbpg5m2NBFHuwj-Aw6Km0xMD1FJBOntGDs6wFrIo1m8symz_kj8RjM7oqe6HLwc_Kn5iahdiAvMxBe_JaHO-Gu7ae_e1GmDOy6dUniAsFanAK54fqI8G28aFK8_P1bAOYOCZolRbeirIzLOgVLPXTHPVvPnQwQu3kDicUyudUbLp-WdBsXilyAT0luMqJpXcCeEy9rZB6i2dFUCtYHn-bkyYmGONzPmCe3LL2V764a_QQljT0oASoEBQwjGIDEwCP-YEi9ZPL7HEZ6hyrKdgcnmdlsd4cRoieEjtqMW2HT5EHfO8-pfZHW0LrCnW0n6xHKKFDXvncqEx2TfQazpN0ZFPE_ewt3fP-ZkWmQdIDG2uUvPfl0kSFcdu9uT6wlarldgW--AwtZyG9XtgOZ8M3MCIJuVvX156wz0AKjwTXG0l0I68FwTMwd_b79nLC9cQ28neRTxB8VVhYDL9BDTbxs4deMzWG51qCxJC2CAA-0CdzBcO_7r7IxuUdULnn97BBA3-fsveSRk6HzCDTm5y9Fny6WRP3FqI98yvcsIdfwrjjsZ09ERSPrcKuPkva7ykUDx59tvfKk0JQC8ZULItV-0EYsbweRGRhDPJbDmXqcXLXMqU0zQXZNsh38Q2OSajq210UQsdUvtRSDY8fCDXQ"},
		},
		"WORKATO_DEVELOPER_API_TOKEN_SG": {
			{input: "wrkasg-eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJzdWIiOiI0NzcwZjU1Ny1mNzM2LTQxNDEtYWMzMS0wZTc5OWRhNDBjYjciLCJqdGkiOiJiOWZjNjgxZC1hNjYyLTQwOTMtYTUzMi1lYzAwMDMwZjc3N2UiLCJleHAiOjE3MDU0ODQ4ODd9.kGNst6pqLGNYAUNZmUuABIq0XqqGZeyPS8qAeUCmXpFZlovcJgjfQ-aaX0bhZFUVk3DhWr_DKiH1x9mPtPuH4ACeX2snGv-Pjywd2KR6GDUStOEpEvYO8WZKiMHckT6_LwCDrE2sYl5g4sWVHGSe8zNKbFgyePXiIKAH2gP_Xh5MNjsLAEX23ZJSilCqJ6rzeng6drQzzMpp9L3Amrm_xbrxNTyjnlaqek33xMuH47SeWuCJ5TplsYOD4UZAOrtipjRKiDR1cdD96lj3tOMu9cxdEIvVOeH_OaSISWC4VsLhaOisgrbPgURGlCSG3lxjwletZUlTdL2oc0pTuWgNuYpWKekUyPF0lBW8FUZJY2SyTCKauqw4CDspeRxDOYuZeFcibIomOGCZSe-TH78sZy3uGgvXbwzJkpUffZ1Oa7mb5TjF27AF90G68bQtqLkylcJLSLmYzv7jHFVR_Ssv2DU64Ymj8meKfEDaUa8vhBqH6ne7dNBVGRVIIPGHWotUYF-bLTfoXDwi1izhlWUnmzdQlzJfPk3ckfO3SiJ2A__5HBNrOGaLfQcqmTMStyqdEfdTF6ixyPVNVnZHICBCeSQx73WS3b3yP7YksKcdEuc2hWO1U2u4y6OkpqTEIzjRHVPO2Q86pa9zUAleuc0ZhztntM42PTOA9eDDfG__epA"},
		},
		"WORKATO_DEVELOPER_API_TOKEN_US": {
			{input: "wrkaus-eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJzdWIiOiI0NzcwZjU1Ny1mNzM2LTQxNDEtYWMzMS0wZTc5OWRhNDBjYjciLCJqdGkiOiIzOGY5MGFjYS04MTdmLTQ3MWQtOTllNC0xMWFkMDFkMzUxYzQiLCJleHAiOjE3MDU0ODQ4Njd9.jPOojFsBP0tirUaKC9Bt9yUXXSCPDAakdq64H2KTLwyGoT10esTS06A5SB_F-8QU0YV8DTxpwhuI5FqSfjhpWIDxU8xdqnGRs8q_bsR12ktVADdVShbzuYapkXbQnpqgGlzyAvoHf5EBkHBGv-txhEyOHMnGQJlsQiEqnTT28k4AuDSl2bsz27O7D-Z7SAM1R7TsooJFYM2Nt75oMXqpi0TGyAJeDEXWRLndyYE1JGYDju5k6guOL55s3iOrPdvsexwwUtW-1Rs2k2MyxNcPW5K3UmIgP_yFOcZsOerCLmfvAD3BJhKJzntIOVEw1SbaP8NMVlOX6sB--4RTMtwLmNUYaraOXJW2HZdA4zfX2xrq--_7vN4c2VVHkS7vCNZOZGS0_Q5PTjFafP1WAq-zcqbmMZ0UKBgy0EYA7hv3ZPOt3SKUtu9XTIwuiaWnxNmCqkuYIh6zmogaedoRZsJUiwf55Rjfpa5w1sr_cBa-oWE2W2RCPHoip3fsdSTHbv1supVfs2wEPk0qZLf0t-zDQD561oKbX7rH-BFQpws-ahu2mp82gQcfAVxdbyCCqyzflIm_jUj8tx_wPpSrz_1uO-g706URPjFzrUXoeJ8PLZ34JuMJQDO8XCYbTfvdZVuFFn_7WSe2M7eczikuPHlbX6O6mppO6f1bAfGO4MAspn4"},
			{input: "wrkaus-eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJzdWIiOiI0NzcwZjU1Ny1mNzM2LTQxNDEtYWMzMS0wZTc5OWRhNDBjYjciLCJqdGkiOiJmNDdjMTMyNi04YTRmLTQzYjQtYTVkMy1iNTQzYmE4NTNlOWQiLCJleHAiOjE3MDU0ODQ4Nzh9.KnQYrSBlzHbDD98qSdHdaiK_gdlx7andcFsnXAdmp36acnrdvTSgJaYpIS8k4p77O2U6IXv5Y34Va-RALzUQ3kTDPQFwZAumUEtqM8rcvVv7C7JBIjlU95_jB1oEgfpuBD9ierr2l6aInhKeQW4L8mraHrExOI6-AjSjXOFt6DT4LK3TV_tfYWxmZtizrf9Pl29h3RsB_5jBgf2j1qVGeNzYDXegxIJi6rCC9lM-ziIe5ZkCbVChlc34p6Q7xTSYsxvrcBuMQIJ_tINBStLR0ASj_-XcxMagZbUz_03JUgGfOubt4ckdXwP-2XK6fMzJPxDJL133Kr2_BGp0na1BuAC1BbK5NG890uzJT6BX_iK1sO8POhjkZ0yQdEPVcoB7wKnBHeWAmC0LSaWa7E3NCnNNeZ3E5UbC9DvSlHxwdz8-rTbEltEyYuI24IshZNel7VwUTtYIeCMIZ3nT_nSoKK1TbBlS7hDkdCbC7WHfIdmbmAXBkB3yEdyp1MQLsOTgrS9VfGqPCsV4ilGW14CfcDTckE4MP1i1qvYeUcwWRILXdmO__0_UGDPcRWcJuqBLeveP-JDJo74VBdTVcRI0dydf6i5v-ov30hYZ0IazBTarZJbX_AZyanus0EUQE6bvCbIByRmtUl8d2a21HyFBWUQq450I48DPe6fwsurKhSA"},
		},
		"WORKOS_PRODUCTION_API_KEY": {
			// Generated at https://dashboard.workos.com/
			{input: "sk_a2V5XzAxRlMzQkpXQ1g3QlA3QldFQVBOUDNIU0tTLGVLOTdkcWNadkdDSXNxbVNXbXVDMEtRYVc"},
		},
		"WORKOS_STAGING_API_KEY": {
			// Generated at https://dashboard.workos.com/
			{input: "sk_test_a2V5XzAxRlMzQkQxTUFETlJNNDU0R1RNS1Q0Sjg4LFo2QWdXcVg3b2NDQWlNWUVpZ1E0V1l1WXk"},
		},
		"YANDEX_CLOUD_IAM_TOKEN_V1": {
			{
				input:   "YC_TOKEN=t1.9f7P7fy2m87l9_dXQSMT-u_-3ff3F3AgE_rv_tXu9fickJGMkJOa7fmQj5qRlps=.tMiX952V4Q3T6c5RSBMv6TeZ5DPQHT4hbBR9EgUNvApjK_gi8OMEkzekju512LkR6figaq-P5fI2_i82pBx8Bg==",
				matches: []string{"t1.9f7P7fy2m87l9_dXQSMT-u_-3ff3F3AgE_rv_tXu9fickJGMkJOa7fmQj5qRlps=.tMiX952V4Q3T6c5RSBMv6TeZ5DPQHT4hbBR9EgUNvApjK_gi8OMEkzekju512LkR6figaq-P5fI2_i82pBx8Bg=="},
			},
		},
		"YANDEX_CLOUD_IAM_COOKIE_V1": {
			{
				input:   "YC_COOKIE=c1.9f7P7fy2m87l9_dXQSMT-u_-3ff3F3AgE_rv_tXu9fickJGMkJOa7fmQj5qRlps=.tMiX952V4Q3T6c5RSBMv6TeZ5DPQHT4hbBR9EgUNvApjK_gi8OMEkzekju512LkR6figaq-P5fI2_i82pBx8Bg==",
				matches: []string{"c1.9f7P7fy2m87l9_dXQSMT-u_-3ff3F3AgE_rv_tXu9fickJGMkJOa7fmQj5qRlps=.tMiX952V4Q3T6c5RSBMv6TeZ5DPQHT4hbBR9EgUNvApjK_gi8OMEkzekju512LkR6figaq-P5fI2_i82pBx8Bg=="},
			},
		},
		"YANDEX_CLOUD_API_KEY_V1": {
			{
				input:   "YC_TOKEN=AQVN25jmAeB-t_5b7R8H-yUo5s2MHIoYBvEtu9BS",
				matches: []string{"AQVN25jmAeB-t_5b7R8H-yUo5s2MHIoYBvEtu9BS"},
			},
			{
				input:          "SomeBase64+AQVN25jmAeBAtA5b7R8HAyUo5s2MHIoYBvEtu9BS+SomeBase64",
				shouldNotMatch: true,
			},
		},
		"YANDEX_CLOUD_IAM_ACCESS_SECRET": {
			{input: "YCOYr4KovDq4GSeWUsNi0N_OkSLy71VfaVL0jMBZ"},
			{input: "YCNWBVKkZaHnWYJMtygKPjy0QA-hVmBPJQI7kbeR"},
		},
		"YANDEX_DICTIONARY_API_KEY_V1": {
			// Generated at https://yandex.com/dev/dictionary/keys/get/
			{input: "dict.1.1.20211227T013126Z.4d68799fb9ef4905.31c71e863960adcb8a70ebe18c450769770ceeca"},
		},
		"YANDEX_PASSPORT_OAUTH_TOKEN": {
			{input: "y0_AQAAAABh3idvAAAVswAAAADHfXR-8f3cYVgiSyeiqWwl5AxRl23aN58"},
		},
		"YANDEX_PREDICTOR_API_KEY_V1": {
			// Generated at https://yandex.com/dev/predictor/keys/get/
			{input: "pdct.1.1.20210916T233213Z.3dda1fb387fecf17.b8152a4dc486c4bc07b79898477642501c965bad"},
		},
		"YANDEX_TRANSLATE_API_KEY_V1": {
			{input: "trnsl.1.1.20170329T050632Z.750100a4f722eb56.f0e4b9018a16a51fdd44edb6127dda04869cc9c0"},
		},
		"YARN_LOCK_RESOLVED": {
			{
				input:   "  resolved \"https://registry.yarnpkg.com/@webassemblyjs/wasm-gen/-/wasm-gen-1.7.11.tgz#9bbba942f22375686a6fb759afcd7ac9c45da1a8\"",
				matches: []string{"resolved \"https://registry.yarnpkg.com"},
			},
			{
				input:   "  resolved \"https://registry.npmjs.org/@webassemblyjs/wasm-gen/-/wasm-gen-1.7.11.tgz#9bbba942f22375686a6fb759afcd7ac9c45da1a8\"",
				matches: []string{"resolved \"https://registry.npmjs.org"},
			},
		},
		"YARN_LOCK_INTEGRITY": {
			{
				input:   "  integrity sha512-7pvAdC4B+iKjFFp9Ztj0QgBndJ++qaMeonT185wAqUnhipw8idm9Rv1UMyBuKtYjfl6ORNkgEgcsYLfHX/GpLw==",
				matches: []string{"integrity sha512"},
			},
			{
				input:   "  integrity sha1-l6ERlkmyEa0zaR2fn0hqjsn74KM=",
				matches: []string{"integrity sha1"},
			},
		},
		"ZUPLO_CONSUMER_API_KEY": {
			{input: "zpka_dace9cfab42e49e7bc7ae165f72f791b_57b71195"},
			{input: "zpka_0b2a30ec8c654db398b3807d73d81549_397727db"},
			{input: "zpka_3fc4bbe260464dffa3c9c2d52a843284_6446ffad"},
			{input: "zpka_4cbe10c96ea24ad9a633c847547101da_23d5a692"},
			{input: "zpka_1a6cfaa6185f445aba346cfcb6dc4dab_076a6daa"},
			{input: "zpka_e488f12ae412457680cfddaa09214e7f_57869f93"},
		},
	}
)

func TestMatchSimple(t *testing.T) {
	t.Parallel()
	checkPatternsMatchExamples(t, "%s")
}

func TestMatchStart(t *testing.T) {
	t.Parallel()
	checkPatternsMatchExamples(t, "%s\nasdf\nasdf")
}

func TestMatchEnd(t *testing.T) {
	t.Parallel()
	checkPatternsMatchExamples(t, "asdf\nasdf\n%s")
}

func TestMatchQuoted(t *testing.T) {
	t.Parallel()
	checkPatternsMatchExamples(t, "secret = \"%s\"")
}

func TestMatchInBinary(t *testing.T) {
	t.Parallel()
	checkPatternsMatchExamples(t, "\x74\x27\x4a\xb3\x35\x95\xd4\x8a%s\xea\x58\xc2\xb3\x44\x68\x70\xe2")
}

func TestMatchName(t *testing.T) {
	t.Parallel()
	checkPatternsMatchExamples(t, "%s = samplestring")
}

func TestZipScanEnablement(t *testing.T) {
	t.Parallel()
	logger := NewSysLogger("")
	ctx := context.Background()
	statter := stats.NullStatter
	reporter := NewEmptyExceptionReporter()

	// Load a zip file
	var buf = [1e4]byte{} // 10mb
	file, openErr := os.Open(zipResourcesPath + "zip_test.zip")
	require.NoError(t, openErr)
	size, err := file.Read(buf[:])
	require.NoError(t, err)
	require.True(t, IsZipFile(buf[:size]))

	// ADAFRUIT is the kind of token stored in zip_test.zip
	db, err := getConfig("ADAFRUIT_AIO_KEY").Database()
	require.NoError(t, err)

	scratch, err := hyperscan.NewScratch(db)
	require.NoError(t, err)

	var scanZips bool

	t.Run("does not detect results when set to NOT scan zips", func(t *testing.T) {
		t.Parallel()
		fb := newFixtureBlob(string(buf[:size]))

		// Evaluate "don't scan zips"
		cbUnexpected := func(providerIdx uint, sha string, content []byte, match []byte, from, to uint64, _ *BlobContext, sc stats.Client) error {
			t.Errorf("No secrets should have been found")
			return nil
		}
		dbWithCallback := []*DatabaseWithCallback{{
			Database: db,
			Callback: cbUnexpected,
		}}

		err = ScanWithScratchV2(ctx, logger, reporter, statter, fb, dbWithCallback, scratch, false)
		require.NoError(t, err)
	})

	t.Run("detects results when set to scan zips", func(t *testing.T) {
		fb := newFixtureBlob(string(buf[:size]))

		// Evaluate "do scan zips"
		called := false
		cbExpected := func(providerIdx uint, sha string, content []byte, match []byte, from, to uint64, _ *BlobContext, sc stats.Client) error {
			called = true
			return nil
		}
		scanZips = true
		dbWithCallback := []*DatabaseWithCallback{{
			Database: db,
			Callback: cbExpected,
		}}

		err = ScanWithScratchV2(ctx, logger, reporter, statter, fb, dbWithCallback, scratch, scanZips)
		require.NoError(t, err)
		require.True(t, called, "Expected to find a secret")
	})
}

func TestAllHyperscanProvidersHaveExamples(t *testing.T) {
	t.Parallel()
	for _, provider := range prodConfig.HyperscanProviders() {
		if provider.Name == "GENERIC_JWT" {
			// The GENERIC_JWT is special cased in NewScanCallback, so we don't test
			// it here
			continue
		}

		if exampleTokens[provider.Name] == nil {
			t.Errorf("Missing token examples for '%s' provider", provider.Name)
		}
	}
}

func checkPatternsMatchExamples(t *testing.T, format string) {
	t.Helper()
	logger := NewSysLogger("")
	ctx := context.Background()
	statter := stats.NullStatter
	reporter := NewEmptyExceptionReporter()

	filter := processors.NewChainFilter(processors.LengthFilter(0), processors.ExactLengthFilter(), processors.AlternativeMatchFilter()) // minimal filters
	matchProcessor := NewTestMatchProcessor()
	cb := NewScanCallback(context.Background(), NewSysLogger(""), NewEmptyExceptionReporter(), prodConfig, filter, matchProcessor)
	db, err := prodConfig.Database()
	if err != nil {
		t.Fatal(err)
	}

	focusedProviderNames := make(config.StringSet)
	scratch, err := hyperscan.NewScratch(db)
	require.NoError(t, err)
	defer func() {
		err := scratch.Free()
		require.NoError(t, err)
	}()

	for providerName, examples := range exampleTokens {
		if len(focusedProviderNames) > 0 && !focusedProviderNames.Has(providerName) {
			continue
		}

		scanZipFiles := true
		for _, example := range examples {
			matchProcessor.Reset()
			fb := newFixtureBlob(fmt.Sprintf(format, example.input))
			require.NoError(t, err)

			dbWithCallback := []*DatabaseWithCallback{{
				Database: db,
				Callback: cb,
			}}

			err = ScanWithScratchV2(ctx, logger, reporter, statter, fb, dbWithCallback, scratch, scanZipFiles)
			require.NoError(t, err)

			for _, expectedMatch := range example.expectedMatches() {
				require.True(t,
					matchProcessor.ContainsToken(providerName, expectedMatch),
					fmt.Sprintf("expected a match for %s when scanning for %s", expectedMatch, providerName))
			}

			require.Equal(t, len(example.expectedMatches()), matchProcessor.TokenCount(providerName))
		}
	}
}

func init() { // nolint: gochecknoinits
	var err error
	if prodConfig, err = config.LoadDefaultConfig(); err != nil {
		panic(err)
	}
}

func getConfig(providerName string) *config.Config {
	for _, providerConfig := range config.GetDefaultConfig() {
		if providerConfig.Name == providerName {
			cfg, err := config.LoadCustomConfig([]*config.ProviderConfig{providerConfig})
			if err != nil {
				return nil
			}
			return cfg
		}
	}
	return nil
}

type exampleToken struct {
	input          string
	matches        []string
	shouldNotMatch bool
}

func (et *exampleToken) expectedMatches() []string {
	if et.shouldNotMatch {
		return []string{}
	}
	if len(et.matches) > 0 {
		return et.matches
	}
	return []string{et.input}
}
