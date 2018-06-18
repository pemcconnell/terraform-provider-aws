package aws

import (
	"fmt"
	"strconv"
	"testing"

	"os"
	"regexp"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/acm"
	"github.com/hashicorp/terraform/helper/acctest"
	"github.com/hashicorp/terraform/helper/resource"
	"github.com/hashicorp/terraform/terraform"
)

var certificateArnRegex = regexp.MustCompile(`^arn:aws:acm:[^:]+:[^:]+:certificate/.+$`)

func testAccAwsAcmCertificateDomainFromEnv(t *testing.T) string {
	if os.Getenv("ACM_CERTIFICATE_ROOT_DOMAIN") == "" {
		t.Skip(
			"Environment variable ACM_CERTIFICATE_ROOT_DOMAIN is not set. " +
				"For DNS validation requests, this domain must be publicly " +
				"accessible and configurable via Route53 during the testing. " +
				"For email validation requests, you must have access to one of " +
				"the five standard email addresses used (admin|administrator|" +
				"hostmaster|postmaster|webmaster)@domain or one of the WHOIS " +
				"contact addresses.")
	}
	return os.Getenv("ACM_CERTIFICATE_ROOT_DOMAIN")
}

func TestAccAWSAcmCertificate_emailValidation(t *testing.T) {
	rootDomain := testAccAwsAcmCertificateDomainFromEnv(t)

	rInt1 := acctest.RandInt()

	domain := fmt.Sprintf("tf-acc-%d.%s", rInt1, rootDomain)

	resource.Test(t, resource.TestCase{
		PreCheck:     func() { testAccPreCheck(t) },
		Providers:    testAccProviders,
		CheckDestroy: testAccCheckAcmCertificateDestroy,
		Steps: []resource.TestStep{
			resource.TestStep{
				Config: testAccAcmCertificateConfig(domain, acm.ValidationMethodEmail),
				Check: resource.ComposeTestCheckFunc(
					resource.TestMatchResourceAttr("aws_acm_certificate.cert", "arn", certificateArnRegex),
					resource.TestCheckResourceAttr("aws_acm_certificate.cert", "domain_name", domain),
					resource.TestCheckResourceAttr("aws_acm_certificate.cert", "domain_validation_options.#", "0"),
					resource.TestCheckResourceAttr("aws_acm_certificate.cert", "subject_alternative_names.#", "0"),
					resource.TestMatchResourceAttr("aws_acm_certificate.cert", "validation_emails.0", regexp.MustCompile(`^[^@]+@.+$`)),
					resource.TestCheckResourceAttr("aws_acm_certificate.cert", "validation_method", acm.ValidationMethodEmail),
				),
			},
			resource.TestStep{
				ResourceName:      "aws_acm_certificate.cert",
				ImportState:       true,
				ImportStateVerify: true,
			},
		},
	})

}

func TestAccAWSAcmCertificate_dnsValidation(t *testing.T) {
	rootDomain := testAccAwsAcmCertificateDomainFromEnv(t)

	rInt1 := acctest.RandInt()

	domain := fmt.Sprintf("tf-acc-%d.%s", rInt1, rootDomain)

	resource.Test(t, resource.TestCase{
		PreCheck:     func() { testAccPreCheck(t) },
		Providers:    testAccProviders,
		CheckDestroy: testAccCheckAcmCertificateDestroy,
		Steps: []resource.TestStep{
			resource.TestStep{
				Config: testAccAcmCertificateConfig(domain, acm.ValidationMethodDns),
				Check: resource.ComposeTestCheckFunc(
					resource.TestMatchResourceAttr("aws_acm_certificate.cert", "arn", certificateArnRegex),
					resource.TestCheckResourceAttr("aws_acm_certificate.cert", "domain_name", domain),
					resource.TestCheckResourceAttr("aws_acm_certificate.cert", "domain_validation_options.#", "1"),
					resource.TestCheckResourceAttr("aws_acm_certificate.cert", "domain_validation_options.0.domain_name", domain),
					resource.TestCheckResourceAttrSet("aws_acm_certificate.cert", "domain_validation_options.0.resource_record_name"),
					resource.TestCheckResourceAttr("aws_acm_certificate.cert", "domain_validation_options.0.resource_record_type", "CNAME"),
					resource.TestCheckResourceAttrSet("aws_acm_certificate.cert", "domain_validation_options.0.resource_record_value"),
					resource.TestCheckResourceAttr("aws_acm_certificate.cert", "subject_alternative_names.#", "0"),
					resource.TestCheckResourceAttr("aws_acm_certificate.cert", "validation_emails.#", "0"),
					resource.TestCheckResourceAttr("aws_acm_certificate.cert", "validation_method", acm.ValidationMethodDns),
				),
			},
			resource.TestStep{
				ResourceName:      "aws_acm_certificate.cert",
				ImportState:       true,
				ImportStateVerify: true,
			},
		},
	})
}

func TestAccAWSAcmCertificate_root(t *testing.T) {
	rootDomain := testAccAwsAcmCertificateDomainFromEnv(t)

	resource.Test(t, resource.TestCase{
		PreCheck:     func() { testAccPreCheck(t) },
		Providers:    testAccProviders,
		CheckDestroy: testAccCheckAcmCertificateDestroy,
		Steps: []resource.TestStep{
			resource.TestStep{
				Config: testAccAcmCertificateConfig(rootDomain, acm.ValidationMethodDns),
				Check: resource.ComposeTestCheckFunc(
					resource.TestMatchResourceAttr("aws_acm_certificate.cert", "arn", certificateArnRegex),
					resource.TestCheckResourceAttr("aws_acm_certificate.cert", "domain_name", rootDomain),
					resource.TestCheckResourceAttr("aws_acm_certificate.cert", "domain_validation_options.#", "1"),
					resource.TestCheckResourceAttr("aws_acm_certificate.cert", "domain_validation_options.0.domain_name", rootDomain),
					resource.TestCheckResourceAttrSet("aws_acm_certificate.cert", "domain_validation_options.0.resource_record_name"),
					resource.TestCheckResourceAttr("aws_acm_certificate.cert", "domain_validation_options.0.resource_record_type", "CNAME"),
					resource.TestCheckResourceAttrSet("aws_acm_certificate.cert", "domain_validation_options.0.resource_record_value"),
					resource.TestCheckResourceAttr("aws_acm_certificate.cert", "subject_alternative_names.#", "0"),
					resource.TestCheckResourceAttr("aws_acm_certificate.cert", "validation_emails.#", "0"),
					resource.TestCheckResourceAttr("aws_acm_certificate.cert", "validation_method", acm.ValidationMethodDns),
				),
			},
			resource.TestStep{
				ResourceName:      "aws_acm_certificate.cert",
				ImportState:       true,
				ImportStateVerify: true,
			},
		},
	})
}

func TestAccAWSAcmCertificate_rootAndWildcardSan(t *testing.T) {
	rootDomain := testAccAwsAcmCertificateDomainFromEnv(t)
	wildcardDomain := fmt.Sprintf("*.%s", rootDomain)

	resource.Test(t, resource.TestCase{
		PreCheck:     func() { testAccPreCheck(t) },
		Providers:    testAccProviders,
		CheckDestroy: testAccCheckAcmCertificateDestroy,
		Steps: []resource.TestStep{
			resource.TestStep{
				Config: testAccAcmCertificateConfig_subjectAlternativeNames(rootDomain, strconv.Quote(wildcardDomain), acm.ValidationMethodDns),
				Check: resource.ComposeTestCheckFunc(
					resource.TestMatchResourceAttr("aws_acm_certificate.cert", "arn", certificateArnRegex),
					resource.TestCheckResourceAttr("aws_acm_certificate.cert", "domain_name", rootDomain),
					resource.TestCheckResourceAttr("aws_acm_certificate.cert", "domain_validation_options.#", "2"),
					resource.TestCheckResourceAttr("aws_acm_certificate.cert", "domain_validation_options.0.domain_name", rootDomain),
					resource.TestCheckResourceAttrSet("aws_acm_certificate.cert", "domain_validation_options.0.resource_record_name"),
					resource.TestCheckResourceAttr("aws_acm_certificate.cert", "domain_validation_options.0.resource_record_type", "CNAME"),
					resource.TestCheckResourceAttrSet("aws_acm_certificate.cert", "domain_validation_options.0.resource_record_value"),
					resource.TestCheckResourceAttr("aws_acm_certificate.cert", "domain_validation_options.1.domain_name", wildcardDomain),
					resource.TestCheckResourceAttrSet("aws_acm_certificate.cert", "domain_validation_options.1.resource_record_name"),
					resource.TestCheckResourceAttr("aws_acm_certificate.cert", "domain_validation_options.1.resource_record_type", "CNAME"),
					resource.TestCheckResourceAttrSet("aws_acm_certificate.cert", "domain_validation_options.1.resource_record_value"),
					resource.TestCheckResourceAttr("aws_acm_certificate.cert", "subject_alternative_names.#", "1"),
					resource.TestCheckResourceAttr("aws_acm_certificate.cert", "subject_alternative_names.0", wildcardDomain),
					resource.TestCheckResourceAttr("aws_acm_certificate.cert", "validation_emails.#", "0"),
					resource.TestCheckResourceAttr("aws_acm_certificate.cert", "validation_method", acm.ValidationMethodDns),
				),
			},
			resource.TestStep{
				ResourceName:      "aws_acm_certificate.cert",
				ImportState:       true,
				ImportStateVerify: true,
			},
		},
	})
}

func TestAccAWSAcmCertificate_san_single(t *testing.T) {
	rootDomain := testAccAwsAcmCertificateDomainFromEnv(t)

	rInt1 := acctest.RandInt()

	domain := fmt.Sprintf("tf-acc-%d.%s", rInt1, rootDomain)
	sanDomain := fmt.Sprintf("tf-acc-%d-san.%s", rInt1, rootDomain)

	resource.Test(t, resource.TestCase{
		PreCheck:     func() { testAccPreCheck(t) },
		Providers:    testAccProviders,
		CheckDestroy: testAccCheckAcmCertificateDestroy,
		Steps: []resource.TestStep{
			resource.TestStep{
				Config: testAccAcmCertificateConfig_subjectAlternativeNames(domain, strconv.Quote(sanDomain), acm.ValidationMethodDns),
				Check: resource.ComposeTestCheckFunc(
					resource.TestMatchResourceAttr("aws_acm_certificate.cert", "arn", certificateArnRegex),
					resource.TestCheckResourceAttr("aws_acm_certificate.cert", "domain_name", domain),
					resource.TestCheckResourceAttr("aws_acm_certificate.cert", "domain_validation_options.#", "2"),
					resource.TestCheckResourceAttr("aws_acm_certificate.cert", "domain_validation_options.0.domain_name", domain),
					resource.TestCheckResourceAttrSet("aws_acm_certificate.cert", "domain_validation_options.0.resource_record_name"),
					resource.TestCheckResourceAttr("aws_acm_certificate.cert", "domain_validation_options.0.resource_record_type", "CNAME"),
					resource.TestCheckResourceAttrSet("aws_acm_certificate.cert", "domain_validation_options.0.resource_record_value"),
					resource.TestCheckResourceAttr("aws_acm_certificate.cert", "domain_validation_options.1.domain_name", sanDomain),
					resource.TestCheckResourceAttrSet("aws_acm_certificate.cert", "domain_validation_options.1.resource_record_name"),
					resource.TestCheckResourceAttr("aws_acm_certificate.cert", "domain_validation_options.1.resource_record_type", "CNAME"),
					resource.TestCheckResourceAttrSet("aws_acm_certificate.cert", "domain_validation_options.1.resource_record_value"),
					resource.TestCheckResourceAttr("aws_acm_certificate.cert", "subject_alternative_names.#", "1"),
					resource.TestCheckResourceAttr("aws_acm_certificate.cert", "subject_alternative_names.0", sanDomain),
					resource.TestCheckResourceAttr("aws_acm_certificate.cert", "validation_emails.#", "0"),
					resource.TestCheckResourceAttr("aws_acm_certificate.cert", "validation_method", acm.ValidationMethodDns),
				),
			},
			resource.TestStep{
				ResourceName:      "aws_acm_certificate.cert",
				ImportState:       true,
				ImportStateVerify: true,
			},
		},
	})
}

func TestAccAWSAcmCertificate_san_multiple(t *testing.T) {
	rootDomain := testAccAwsAcmCertificateDomainFromEnv(t)

	rInt1 := acctest.RandInt()

	domain := fmt.Sprintf("tf-acc-%d.%s", rInt1, rootDomain)
	sanDomain1 := fmt.Sprintf("tf-acc-%d-san1.%s", rInt1, rootDomain)
	sanDomain2 := fmt.Sprintf("tf-acc-%d-san2.%s", rInt1, rootDomain)

	resource.Test(t, resource.TestCase{
		PreCheck:     func() { testAccPreCheck(t) },
		Providers:    testAccProviders,
		CheckDestroy: testAccCheckAcmCertificateDestroy,
		Steps: []resource.TestStep{
			resource.TestStep{
				Config: testAccAcmCertificateConfig_subjectAlternativeNames(domain, fmt.Sprintf("%q, %q", sanDomain1, sanDomain2), acm.ValidationMethodDns),
				Check: resource.ComposeTestCheckFunc(
					resource.TestMatchResourceAttr("aws_acm_certificate.cert", "arn", certificateArnRegex),
					resource.TestCheckResourceAttr("aws_acm_certificate.cert", "domain_name", domain),
					resource.TestCheckResourceAttr("aws_acm_certificate.cert", "domain_validation_options.#", "3"),
					resource.TestCheckResourceAttr("aws_acm_certificate.cert", "domain_validation_options.0.domain_name", domain),
					resource.TestCheckResourceAttrSet("aws_acm_certificate.cert", "domain_validation_options.0.resource_record_name"),
					resource.TestCheckResourceAttr("aws_acm_certificate.cert", "domain_validation_options.0.resource_record_type", "CNAME"),
					resource.TestCheckResourceAttrSet("aws_acm_certificate.cert", "domain_validation_options.0.resource_record_value"),
					resource.TestCheckResourceAttr("aws_acm_certificate.cert", "domain_validation_options.1.domain_name", sanDomain1),
					resource.TestCheckResourceAttrSet("aws_acm_certificate.cert", "domain_validation_options.1.resource_record_name"),
					resource.TestCheckResourceAttr("aws_acm_certificate.cert", "domain_validation_options.1.resource_record_type", "CNAME"),
					resource.TestCheckResourceAttrSet("aws_acm_certificate.cert", "domain_validation_options.1.resource_record_value"),
					resource.TestCheckResourceAttr("aws_acm_certificate.cert", "domain_validation_options.2.domain_name", sanDomain2),
					resource.TestCheckResourceAttrSet("aws_acm_certificate.cert", "domain_validation_options.2.resource_record_name"),
					resource.TestCheckResourceAttr("aws_acm_certificate.cert", "domain_validation_options.2.resource_record_type", "CNAME"),
					resource.TestCheckResourceAttrSet("aws_acm_certificate.cert", "domain_validation_options.2.resource_record_value"),
					resource.TestCheckResourceAttr("aws_acm_certificate.cert", "subject_alternative_names.#", "2"),
					resource.TestCheckResourceAttr("aws_acm_certificate.cert", "subject_alternative_names.0", sanDomain1),
					resource.TestCheckResourceAttr("aws_acm_certificate.cert", "subject_alternative_names.1", sanDomain2),
					resource.TestCheckResourceAttr("aws_acm_certificate.cert", "validation_emails.#", "0"),
					resource.TestCheckResourceAttr("aws_acm_certificate.cert", "validation_method", acm.ValidationMethodDns),
				),
			},
			resource.TestStep{
				ResourceName:      "aws_acm_certificate.cert",
				ImportState:       true,
				ImportStateVerify: true,
			},
		},
	})
}

func TestAccAWSAcmCertificate_wildcard(t *testing.T) {
	rootDomain := testAccAwsAcmCertificateDomainFromEnv(t)
	wildcardDomain := fmt.Sprintf("*.%s", rootDomain)

	resource.Test(t, resource.TestCase{
		PreCheck:     func() { testAccPreCheck(t) },
		Providers:    testAccProviders,
		CheckDestroy: testAccCheckAcmCertificateDestroy,
		Steps: []resource.TestStep{
			resource.TestStep{
				Config: testAccAcmCertificateConfig(wildcardDomain, acm.ValidationMethodDns),
				Check: resource.ComposeTestCheckFunc(
					resource.TestMatchResourceAttr("aws_acm_certificate.cert", "arn", certificateArnRegex),
					resource.TestCheckResourceAttr("aws_acm_certificate.cert", "domain_name", wildcardDomain),
					resource.TestCheckResourceAttr("aws_acm_certificate.cert", "domain_validation_options.#", "1"),
					resource.TestCheckResourceAttr("aws_acm_certificate.cert", "domain_validation_options.0.domain_name", wildcardDomain),
					resource.TestCheckResourceAttrSet("aws_acm_certificate.cert", "domain_validation_options.0.resource_record_name"),
					resource.TestCheckResourceAttr("aws_acm_certificate.cert", "domain_validation_options.0.resource_record_type", "CNAME"),
					resource.TestCheckResourceAttrSet("aws_acm_certificate.cert", "domain_validation_options.0.resource_record_value"),
					resource.TestCheckResourceAttr("aws_acm_certificate.cert", "subject_alternative_names.#", "0"),
					resource.TestCheckResourceAttr("aws_acm_certificate.cert", "validation_emails.#", "0"),
					resource.TestCheckResourceAttr("aws_acm_certificate.cert", "validation_method", acm.ValidationMethodDns),
				),
			},
			resource.TestStep{
				ResourceName:      "aws_acm_certificate.cert",
				ImportState:       true,
				ImportStateVerify: true,
			},
		},
	})
}

func TestAccAWSAcmCertificate_wildcardAndRootSan(t *testing.T) {
	rootDomain := testAccAwsAcmCertificateDomainFromEnv(t)
	wildcardDomain := fmt.Sprintf("*.%s", rootDomain)

	resource.Test(t, resource.TestCase{
		PreCheck:     func() { testAccPreCheck(t) },
		Providers:    testAccProviders,
		CheckDestroy: testAccCheckAcmCertificateDestroy,
		Steps: []resource.TestStep{
			resource.TestStep{
				Config: testAccAcmCertificateConfig_subjectAlternativeNames(wildcardDomain, strconv.Quote(rootDomain), acm.ValidationMethodDns),
				Check: resource.ComposeTestCheckFunc(
					resource.TestMatchResourceAttr("aws_acm_certificate.cert", "arn", certificateArnRegex),
					resource.TestCheckResourceAttr("aws_acm_certificate.cert", "domain_name", wildcardDomain),
					resource.TestCheckResourceAttr("aws_acm_certificate.cert", "domain_validation_options.#", "2"),
					resource.TestCheckResourceAttr("aws_acm_certificate.cert", "domain_validation_options.0.domain_name", wildcardDomain),
					resource.TestCheckResourceAttrSet("aws_acm_certificate.cert", "domain_validation_options.0.resource_record_name"),
					resource.TestCheckResourceAttr("aws_acm_certificate.cert", "domain_validation_options.0.resource_record_type", "CNAME"),
					resource.TestCheckResourceAttrSet("aws_acm_certificate.cert", "domain_validation_options.0.resource_record_value"),
					resource.TestCheckResourceAttr("aws_acm_certificate.cert", "domain_validation_options.1.domain_name", rootDomain),
					resource.TestCheckResourceAttrSet("aws_acm_certificate.cert", "domain_validation_options.1.resource_record_name"),
					resource.TestCheckResourceAttr("aws_acm_certificate.cert", "domain_validation_options.1.resource_record_type", "CNAME"),
					resource.TestCheckResourceAttrSet("aws_acm_certificate.cert", "domain_validation_options.1.resource_record_value"),
					resource.TestCheckResourceAttr("aws_acm_certificate.cert", "subject_alternative_names.#", "1"),
					resource.TestCheckResourceAttr("aws_acm_certificate.cert", "subject_alternative_names.0", rootDomain),
					resource.TestCheckResourceAttr("aws_acm_certificate.cert", "validation_emails.#", "0"),
					resource.TestCheckResourceAttr("aws_acm_certificate.cert", "validation_method", acm.ValidationMethodDns),
				),
			},
			resource.TestStep{
				ResourceName:      "aws_acm_certificate.cert",
				ImportState:       true,
				ImportStateVerify: true,
			},
		},
	})
}

func TestAccAWSAcmCertificate_tags(t *testing.T) {
	rootDomain := testAccAwsAcmCertificateDomainFromEnv(t)

	rInt1 := acctest.RandInt()

	domain := fmt.Sprintf("tf-acc-%d.%s", rInt1, rootDomain)

	resource.Test(t, resource.TestCase{
		PreCheck:     func() { testAccPreCheck(t) },
		Providers:    testAccProviders,
		CheckDestroy: testAccCheckAcmCertificateDestroy,
		Steps: []resource.TestStep{
			resource.TestStep{
				Config: testAccAcmCertificateConfig(domain, acm.ValidationMethodDns),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("aws_acm_certificate.cert", "tags.%", "0"),
				),
			},
			resource.TestStep{
				Config: testAccAcmCertificateConfig_twoTags(domain, acm.ValidationMethodDns, "Hello", "World", "Foo", "Bar"),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("aws_acm_certificate.cert", "tags.%", "2"),
					resource.TestCheckResourceAttr("aws_acm_certificate.cert", "tags.Hello", "World"),
					resource.TestCheckResourceAttr("aws_acm_certificate.cert", "tags.Foo", "Bar"),
				),
			},
			resource.TestStep{
				Config: testAccAcmCertificateConfig_twoTags(domain, acm.ValidationMethodDns, "Hello", "World", "Foo", "Baz"),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("aws_acm_certificate.cert", "tags.%", "2"),
					resource.TestCheckResourceAttr("aws_acm_certificate.cert", "tags.Hello", "World"),
					resource.TestCheckResourceAttr("aws_acm_certificate.cert", "tags.Foo", "Baz"),
				),
			},
			resource.TestStep{
				Config: testAccAcmCertificateConfig_oneTag(domain, acm.ValidationMethodDns, "Environment", "Test"),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("aws_acm_certificate.cert", "tags.%", "1"),
					resource.TestCheckResourceAttr("aws_acm_certificate.cert", "tags.Environment", "Test"),
				),
			},
			resource.TestStep{
				ResourceName:      "aws_acm_certificate.cert",
				ImportState:       true,
				ImportStateVerify: true,
			},
		},
	})
}

func TestAccAcmCertificateImport(t *testing.T) {
	domainName := "server.acme"
	resource.Test(t, resource.TestCase{
		PreCheck:     func() { testAccPreCheck(t) },
		Providers:    testAccProviders,
		CheckDestroy: testAccCheckAcmCertificateDestroy,
		Steps: []resource.TestStep{
			resource.TestStep{
				Config: testAccAcmCertificateImportConfig(domainName, testPrivateKey, testCertBody, testCertChain),
				Check: resource.ComposeTestCheckFunc(
					resource.TestMatchResourceAttr("aws_acm_certificate.cert", "arn", certificateArnRegex),
					resource.TestCheckResourceAttr("aws_acm_certificate.cert", "domain", domainName),
					resource.TestCheckResourceAttr("aws_acm_certificate.cert", "private_key", "5d02aa602c7ace4a5d0bcc62e853cbf30ada0c5b"),
					resource.TestCheckResourceAttr("aws_acm_certificate.cert", "certificate_body", "c916fb0a0a378508b8560f338f7cd4aefaa7a059"),
					resource.TestCheckResourceAttr("aws_acm_certificate.cert", "certificate_chain", "919da276e31028e8728c05be1e0e4f5649ab7a5a"),
					resource.TestCheckResourceAttr("aws_acm_certificate.cert", "tags.%", "0"),
					resource.TestCheckResourceAttr("aws_acm_certificate.cert", "domain_validation_options.#", "0"),
					resource.TestCheckResourceAttr("aws_acm_certificate.cert", "subject_alternative_names.#", "0"),
					resource.TestMatchResourceAttr("aws_acm_certificate.cert", "validation_emails.0", regexp.MustCompile(`^[^@]+@.+$`)),
				),
			},
			resource.TestStep{
				ResourceName:      "aws_acm_certificate.cert",
				ImportState:       true,
				ImportStateVerify: true,
			},
		},
	})
}

func testAccAcmCertificateImportConfig(domainName, privateKey, certificateBody, certificateChain string) string {
	return fmt.Sprintf(`
resource "aws_acm_certificate" "cert" {
  domain_name = "%s"
  private_key = <<EOF
%s
EOF
  certificate_body = <<EOF
%s
EOF
  certificate_chain = <<EOF
%s
EOF
}
`, domainName, privateKey, certificateBody, certificateChain)

}
func testAccAcmCertificateConfig(domainName, validationMethod string) string {
	return fmt.Sprintf(`
resource "aws_acm_certificate" "cert" {
  domain_name       = "%s"
  validation_method = "%s"
}
`, domainName, validationMethod)

}

func testAccAcmCertificateConfig_subjectAlternativeNames(domainName, subjectAlternativeNames, validationMethod string) string {
	return fmt.Sprintf(`
resource "aws_acm_certificate" "cert" {
  domain_name               = "%s"
  subject_alternative_names = [%s]
  validation_method = "%s"
}
`, domainName, subjectAlternativeNames, validationMethod)
}

func testAccAcmCertificateConfig_oneTag(domainName, validationMethod, tag1Key, tag1Value string) string {
	return fmt.Sprintf(`
resource "aws_acm_certificate" "cert" {
  domain_name       = "%s"
  validation_method = "%s"

  tags {
    "%s" = "%s"
  }
}
`, domainName, validationMethod, tag1Key, tag1Value)
}

func testAccAcmCertificateConfig_twoTags(domainName, validationMethod, tag1Key, tag1Value, tag2Key, tag2Value string) string {
	return fmt.Sprintf(`
resource "aws_acm_certificate" "cert" {
  domain_name       = "%s"
  validation_method = "%s"

  tags {
    "%s" = "%s"
    "%s" = "%s"
  }
}
`, domainName, validationMethod, tag1Key, tag1Value, tag2Key, tag2Value)
}

func testAccCheckAcmCertificateDestroy(s *terraform.State) error {
	acmconn := testAccProvider.Meta().(*AWSClient).acmconn

	for _, rs := range s.RootModule().Resources {
		if rs.Type != "aws_acm_certificate" {
			continue
		}
		_, err := acmconn.DescribeCertificate(&acm.DescribeCertificateInput{
			CertificateArn: aws.String(rs.Primary.ID),
		})

		if err == nil {
			return fmt.Errorf("Certificate still exists.")
		}

		// Verify the error is what we want
		if !isAWSErr(err, acm.ErrCodeResourceNotFoundException, "") {
			return err
		}
	}

	return nil
}

const testPrivateKey = `-----BEGIN RSA PRIVATE KEY-----
MIIEogIBAAKCAQEAykz2F/wjDZ9RLRolRujnrJwq4RXy4glnH1rKq6qmKZIxEkdn
BT3coF4yBMaotgwZG1jNx9V/hKRp1bHH6QaW0fmHm+2Ct5iAaqvp02GiCnGJGMJl
zqKazAa2ihEScJydU1ItB+BVUisTFy2B0eSATph7GRxHp9wVlnSeNbPOQ3JwWXe2
IOu2KjQMfYYvanPW30AzhVGlFOFXhN79SSml0yBauU/n2miJgWBPgT63iFyp6+eK
9SrMFqtg6Sq2CV4Oh4yPQSjnCZrreanfBoNLbsKtuvR2P4c8/dkQXiLQNjgKrPxx
AOT07HXFv4v4YJh12q5j9pEmwNEKmlURWQMXKQIDAQABAoIBAFRzwnyKzpteOgYp
Fwy+KBEf9KqYfhesszccsOTvTYSnOgMWecRvac4s5Jan1ECDVmvbK7TTxPM7q88A
86KtFIM9t0X55gr9CAcAE5Ih/QJ9GS2T4epcaWDpIIUM0XTffLIO6SuTlCrEPqj7
X2mfCY1GDIWUD7ncn8p6jp1+nYn72y4kfQNFnvQ+ZwcVaCdTVX7zaLSdOBVbydLC
Jw0CMygyR5GTPK61KDn1r39Q/g+pSxUkDfjN6OJFbF9H7f1WCf9VwheFNjCWKD5B
iEGoBxa1BO+8bOg6t2J8rBE8OA96Axu5qeDgf07TZxmZoQAMICWlfYoVwxjR+WFB
lboe0AECgYEA6AqpnnPP6M4wE0iXlrCPWGHuiYxQ7ud4CLDo6bxulV1jR5dbXnNF
isvvd3+AyAY18NyCsJyAdd91e38YV9XRl2g5TrE7VD7zofgA/MAFxSscevASEIax
tPwA06IqfygP319oL4N0g7MdyJ5qDGijp4t//I0XkH1qwhrwvdfYmSkCgYEA3zAu
tkyozT0zCXb9JQTnUlSza6K7ODKiQNpOOMLjF5+sQL/sTNNj3j0XTT3Rr1AUCgqe
3Z0ASzD8NpIp+Sut24n167p7KtFZkaVGWWOY9jb1w8+Fp0fl2CE/GCO/HTXse/tt
HAwcvdiTXC2xNdOyS0ZqxiWdW3oLTXRoMz6ATgECgYAszZI+pAHq45ToxEVwtRqY
aCBUsqEV39+PXgk6yEVZ1bRLqG/d5sfwqrvMCPRmqrxTi2A4lZ9AIytd8wZSP1i+
sUMPbK0V8Sm9hlM6eiEjFtXi7uOuCTPazCWkt1UZRDT8XkGRmwIuQ7FmgR/c0X93
5DmMG/oGzhCE9gqxvTF3MQKBgDWqEjFHMXdX9cOa1rdl/HDxaMrCsB2NHzJUy2Ye
hhgSDorrGthGI8c2DTpHWPm8WXUopJZIv99UgfBlKK5+8CjPfVAW4LKk79JzWPz5
U7gv8twIM+zK/tr+83rMbZGKe7g79jo+N1L2lkgdvHRi2IX9AoNuW+245KrVCJD5
wEQBAoGAQ3FFGH/XreZIf/c+w+Eq+rFqM9kJnzNGwHcLMAYGiH1TlspCvzAQFMf5
5ICgt1/Vl2XEQL4FDSmA54Mu8nVEJixpkI+Tr9w1yq/IguOKPosT79cAIVsCf6XH
U7hXHWo2zVv3ZWvZwN0AddkA3EaSrgwAJS5hit05fVDq8knkFZE=
-----END RSA PRIVATE KEY-----`

const testCertBody = `-----BEGIN CERTIFICATE-----
MIIEzDCCArQCAWUwDQYJKoZIhvcNAQEFBQAwgbQxCzAJBgNVBAYTAkdCMRYwFAYD
VQQIDA1BY21lIFByb3ZpbmNlMRIwEAYDVQQHDAlBY21lIENpdHkxHjAcBgNVBAoM
FUFjbWUgSW50ZXJtZWRpYXRlIEx0ZDEWMBQGA1UECwwNQWNtZSBPcmcgVW5pdDEa
MBgGA1UEAwwRaW50ZXJtZWRpYXRlLmFjbWUxJTAjBgkqhkiG9w0BCQEWFmFjbWVA
aW50ZXJtZWRpYXRlLmFjbWUwHhcNMTgwNjE4MTA0MjE5WhcNMjEwMzE0MTA0MjE5
WjCBojELMAkGA1UEBhMCR0IxFjAUBgNVBAgMDUFjbWUgUHJvdmluY2UxEjAQBgNV
BAcMCUFjbWUgQ2l0eTEYMBYGA1UECgwPQWNtZSBTZXJ2ZXIgTHRkMRYwFAYDVQQL
DA1BY21lIE9yZyBVbml0MRQwEgYDVQQDDAtzZXJ2ZXIuYWNtZTEfMB0GCSqGSIb3
DQEJARYQYWNtZUBzZXJ2ZXIuYWNtZTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCC
AQoCggEBAMpM9hf8Iw2fUS0aJUbo56ycKuEV8uIJZx9ayquqpimSMRJHZwU93KBe
MgTGqLYMGRtYzcfVf4SkadWxx+kGltH5h5vtgreYgGqr6dNhogpxiRjCZc6imswG
tooREnCcnVNSLQfgVVIrExctgdHkgE6YexkcR6fcFZZ0njWzzkNycFl3tiDrtio0
DH2GL2pz1t9AM4VRpRThV4Te/UkppdMgWrlP59poiYFgT4E+t4hcqevnivUqzBar
YOkqtgleDoeMj0Eo5wma63mp3waDS27Crbr0dj+HPP3ZEF4i0DY4Cqz8cQDk9Ox1
xb+L+GCYddquY/aRJsDRCppVEVkDFykCAwEAATANBgkqhkiG9w0BAQUFAAOCAgEA
T0SjZfipqqMMrkWq3Q8UZVOrcfUvIbv8ZYWzft10hP4M1OcRNz+Zj+Sn9mquHbcZ
CDq97RURmuYWRcbLLH9FIv5CBENNRv+9h5qV89ly7JdBrFDI+2ZDYiNdDCx9zl7L
qEhEJw8OJDWnjsumQdw5yN/AjAVaoAebP/buu1aHp/PfRojqylLYgwr7/93kZ+JT
EVwiVmoIpl4cpF0n94HFTKDBLlH9xkWEUiA2muyv+laXtyl8c6GU/H1lSpt3RRZr
7DF0IB1zGdobzqURdq8uhz5NAHSTilzESlKrNLMQ1Fa8N8q6ypat/ojxCX/c2d8O
bPSfiX2icZ8FqRxMjoW01hU9dnwvlUXh7WXGFlegazw5JwP6/z0giK+X9tfGOhVt
WKXX4DB18Z6XIjF5jkOULhrk9Khm/1Q1Wywe2r5Knd6t8lbn3UpKRcJTlcfbF0q8
ZHIZ+Mlb74wLUteG3sF6AdMB80uKs/4hWdC14qC7VVCIHR3TJ9RiAqPefBAwIHxB
mUr2JI9kMBu8v5CYP6sUa+Hk+6RbyH34Rh21J866d8grZKuwjzelCzRuvp7yJyAp
1XgApntsBvoskX42x+neGkxpnL6OurJc2JlFC3X4j76jY8XFoOtQGcYOfecgvRbz
B7ytntIKLZ0AlkfNKH+DEe7zpDIis9k/lM61y/aIcMs=
-----END CERTIFICATE-----`

const testCertChain = `-----BEGIN CERTIFICATE-----
MIIEzDCCArQCAWUwDQYJKoZIhvcNAQEFBQAwgbQxCzAJBgNVBAYTAkdCMRYwFAYD
VQQIDA1BY21lIFByb3ZpbmNlMRIwEAYDVQQHDAlBY21lIENpdHkxHjAcBgNVBAoM
FUFjbWUgSW50ZXJtZWRpYXRlIEx0ZDEWMBQGA1UECwwNQWNtZSBPcmcgVW5pdDEa
MBgGA1UEAwwRaW50ZXJtZWRpYXRlLmFjbWUxJTAjBgkqhkiG9w0BCQEWFmFjbWVA
aW50ZXJtZWRpYXRlLmFjbWUwHhcNMTgwNjE4MTA0MjE5WhcNMjEwMzE0MTA0MjE5
WjCBojELMAkGA1UEBhMCR0IxFjAUBgNVBAgMDUFjbWUgUHJvdmluY2UxEjAQBgNV
BAcMCUFjbWUgQ2l0eTEYMBYGA1UECgwPQWNtZSBTZXJ2ZXIgTHRkMRYwFAYDVQQL
DA1BY21lIE9yZyBVbml0MRQwEgYDVQQDDAtzZXJ2ZXIuYWNtZTEfMB0GCSqGSIb3
DQEJARYQYWNtZUBzZXJ2ZXIuYWNtZTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCC
AQoCggEBAMpM9hf8Iw2fUS0aJUbo56ycKuEV8uIJZx9ayquqpimSMRJHZwU93KBe
MgTGqLYMGRtYzcfVf4SkadWxx+kGltH5h5vtgreYgGqr6dNhogpxiRjCZc6imswG
tooREnCcnVNSLQfgVVIrExctgdHkgE6YexkcR6fcFZZ0njWzzkNycFl3tiDrtio0
DH2GL2pz1t9AM4VRpRThV4Te/UkppdMgWrlP59poiYFgT4E+t4hcqevnivUqzBar
YOkqtgleDoeMj0Eo5wma63mp3waDS27Crbr0dj+HPP3ZEF4i0DY4Cqz8cQDk9Ox1
xb+L+GCYddquY/aRJsDRCppVEVkDFykCAwEAATANBgkqhkiG9w0BAQUFAAOCAgEA
T0SjZfipqqMMrkWq3Q8UZVOrcfUvIbv8ZYWzft10hP4M1OcRNz+Zj+Sn9mquHbcZ
CDq97RURmuYWRcbLLH9FIv5CBENNRv+9h5qV89ly7JdBrFDI+2ZDYiNdDCx9zl7L
qEhEJw8OJDWnjsumQdw5yN/AjAVaoAebP/buu1aHp/PfRojqylLYgwr7/93kZ+JT
EVwiVmoIpl4cpF0n94HFTKDBLlH9xkWEUiA2muyv+laXtyl8c6GU/H1lSpt3RRZr
7DF0IB1zGdobzqURdq8uhz5NAHSTilzESlKrNLMQ1Fa8N8q6ypat/ojxCX/c2d8O
bPSfiX2icZ8FqRxMjoW01hU9dnwvlUXh7WXGFlegazw5JwP6/z0giK+X9tfGOhVt
WKXX4DB18Z6XIjF5jkOULhrk9Khm/1Q1Wywe2r5Knd6t8lbn3UpKRcJTlcfbF0q8
ZHIZ+Mlb74wLUteG3sF6AdMB80uKs/4hWdC14qC7VVCIHR3TJ9RiAqPefBAwIHxB
mUr2JI9kMBu8v5CYP6sUa+Hk+6RbyH34Rh21J866d8grZKuwjzelCzRuvp7yJyAp
1XgApntsBvoskX42x+neGkxpnL6OurJc2JlFC3X4j76jY8XFoOtQGcYOfecgvRbz
B7ytntIKLZ0AlkfNKH+DEe7zpDIis9k/lM61y/aIcMs=
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIIFzjCCA7YCCQDNx5EUMHgJxjANBgkqhkiG9w0BAQsFADCBnDELMAkGA1UEBhMC
R0IxFjAUBgNVBAgMDUFjbWUgUHJvdmluY2UxEjAQBgNVBAcMCUFjbWUgQ2l0eTER
MA8GA1UECgwIQWNtZSBMdGQxFjAUBgNVBAsMDUFjbWUgT3JnIFVuaXQxFzAVBgNV
BAMMDmFjbWUuYWNtZS5hY21lMR0wGwYJKoZIhvcNAQkBFg5hY21lQGFjbWUuYWNt
ZTAeFw0xODA2MTgxMDM3NTBaFw0yMTAzMTQxMDM3NTBaMIG0MQswCQYDVQQGEwJH
QjEWMBQGA1UECAwNQWNtZSBQcm92aW5jZTESMBAGA1UEBwwJQWNtZSBDaXR5MR4w
HAYDVQQKDBVBY21lIEludGVybWVkaWF0ZSBMdGQxFjAUBgNVBAsMDUFjbWUgT3Jn
IFVuaXQxGjAYBgNVBAMMEWludGVybWVkaWF0ZS5hY21lMSUwIwYJKoZIhvcNAQkB
FhZhY21lQGludGVybWVkaWF0ZS5hY21lMIICIjANBgkqhkiG9w0BAQEFAAOCAg8A
MIICCgKCAgEAsgPBcFz21rzrOcNwb7BNS63V8uwHEtDjM4mNIP9ST8rFYne485Pp
sP8SrzLstmVQQElZ7MMgphitgjA8p5n7kbR3opkwu65oXdNp8/d1t1gv+2IcWVye
LtZTl36/CGz7/OpMD6WmYJ5kRezoQd/Ml4yesmN2ORN4ENZjF5T+3BlWI1iXvQ4y
ZWJ60ERBVFwIU9xioZugz/RHsk7o3vIM4alSoSXldjbYpr7pXp9uIDIep4h/CsQZ
DoRNtDJgLKZmqzadDrMU+74l8q3B/xYFj07q1YdMd1FULCdU9JehoK0GLRbfQgOQ
zqBjwmMR7XIR0Jv3lJk8KqPEcX0oqN6LHyDV1PmwDW+eR7J8jR/ngslaoXVvZe9g
dMr3us15RhgvU+UV6wjQ/JyAZvzHW79JjuoodSlbSfBXfVIEo0wrUD3tytaxCnu6
LpWAUPRzBRtHWcHzHVaPfv2lE1+l/kcFXqwaqo7Yf0uCG1QKFTC/rHxZkM4e8c/C
xjOxPZ+VtzqJnkPxRvaJbsiq2O7hfEM/ntrMx5B+d8VhmN7hG8JGJr/eQZOofGtU
+Gp1xOYUWBRLjeHmgBzFOmP+pRzl2880wmAuoniql6B5/0dquEenieXIwkxms/7O
2/pIWDUBuTXEURuNxCM+iYQsmZaJ5KW0DrBGWYc6H2LAQdmG2L6Zgv0CAwEAATAN
BgkqhkiG9w0BAQsFAAOCAgEAbbcOYhk+OFMzgsWzG4okMEW0B6RHxIj3sf3zaASy
rCyoOBg9+lLVuwH5lWikyr0ZR3tQKUQDrPsy0iTgdEGh9aA5gutAOAd+wSQbCjUF
Qz++cmecCRyc5JpjbZzKgBtIfNodfseVXc5CbRUZjEqznxAFv1lxsGp/JAW6w11N
Vc4hK/MmRcrZ5GU6qooUYwOWdw1iRksKzRmyH+Sc8Wms0lPmQ+lPH6g+UfY2Oa9L
mjBy6GJ0o3oRr+g3MjE+Eh/ifbYVfRMQ3456xjqeON7DYA5TT+FuH3U8HLM3ZBWP
ockS5xN5Kjy4yUSVfrMYclQRBsj9sMMniW87FTjdGBCF8U7uKkuH2qTcYjdumQgj
7ZWRdh7yA4J5C83zX3iÎwOYYMTfGt3GkHrxDASqKfN0phiZbzzan9MqKvuh/nzgsm
OiHsKhEZbXtFsd3TwozcdVi9VC4i+FjM6tEG2jKqqYifxjxj0Ny7flyEFvTXzYo0
dQXlhxQMAnwbMq2U4f6CKDBHQIFUHWZMomUqXFh+rVD/7os2BaRJqflHKKYB35eE
aq5F/zimFeeKib9yb81be+suSadRM6JH60V4ujG/OrT1XGb06CWPxBPiurkopLvT
uTApmhGwPNTMBLkje6hjhP12rCO3UZVurSx9MLTh1UDJTmQU4hke3kTLe9F+4iqu
nvA=
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
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
Sws0touRu1u5I+4PnTuU1bcdQYw=
-----END CERTIFICATE-----`
