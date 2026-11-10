/*
 * Copyright The Kmesh Authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package secret

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	k8sfake "k8s.io/client-go/kubernetes/fake"
	gatewayapiclient "sigs.k8s.io/gateway-api/pkg/client/clientset/versioned"
	gwfake "sigs.k8s.io/gateway-api/pkg/client/clientset/versioned/fake"

	"kmesh.net/kmesh/ctl/utils"
	"kmesh.net/kmesh/pkg/controller/encryption"
	"kmesh.net/kmesh/pkg/kube"
)

// stubCLIClient is the smallest kube.CLIClient that CreateOrUpdateSecret needs.
type stubCLIClient struct {
	k kubernetes.Interface
}

func (s *stubCLIClient) Kube() kubernetes.Interface           { return s.k }
func (*stubCLIClient) GatewayAPI() gatewayapiclient.Interface { return gwfake.NewSimpleClientset() }
func (s *stubCLIClient) PodsForSelector(ctx context.Context, ns string, selectors ...string) (*corev1.PodList, error) {
	return s.k.CoreV1().Pods(ns).List(ctx, metav1.ListOptions{LabelSelector: strings.Join(selectors, ",")})
}

func (*stubCLIClient) NewPortForwarder(string, string, string, int, int) (kube.PortForwarder, error) {
	return nil, nil
}

// runSecretCreate seeds the fake cluster with the given secrets and runs
// `kmeshctl secret create` against it.
func runSecretCreate(t *testing.T, existing ...corev1.Secret) kubernetes.Interface {
	t.Helper()
	k := k8sfake.NewSimpleClientset()
	for i := range existing {
		if _, err := k.CoreV1().Secrets(utils.KmeshNamespace).Create(context.Background(), &existing[i], metav1.CreateOptions{}); err != nil {
			t.Fatal(err)
		}
	}
	clientset, clientInit = &stubCLIClient{k: k}, nil
	t.Cleanup(func() { clientset, clientInit = nil, nil })

	cmd := NewCmd()
	cmd.SetArgs([]string{"create"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("kmeshctl secret create failed: %v", err)
	}
	return k
}

func storedKey(t *testing.T, k kubernetes.Interface) encryption.IpSecKey {
	t.Helper()
	got, err := k.CoreV1().Secrets(utils.KmeshNamespace).Get(context.Background(), SecretName, metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	var key encryption.IpSecKey
	if err := json.Unmarshal(got.Data["ipSec"], &key); err != nil {
		t.Fatal(err)
	}
	return key
}

func ipsecSecret(data string) corev1.Secret {
	return corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: SecretName, Namespace: utils.KmeshNamespace},
		Type:       corev1.SecretTypeOpaque,
		Data:       map[string][]byte{"ipSec": []byte(data)},
	}
}

func TestSecretCreateNewSecretStartsAtSpi1(t *testing.T) {
	k := runSecretCreate(t)
	if key := storedKey(t, k); key.Spi != 1 {
		t.Fatalf("expected spi 1 for a new secret, got %d", key.Spi)
	}
}

func TestSecretCreateRotatesExistingSecret(t *testing.T) {
	k := runSecretCreate(t, ipsecSecret(`{"aeadKeyName":"rfc4106(gcm(aes))","aeadKey":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","length":128,"spi":3}`))
	if key := storedKey(t, k); key.Spi != 4 {
		t.Fatalf("expected spi 4 after rotating a spi 3 secret, got %d", key.Spi)
	}
}

// A secret written by hand or by other tooling may carry no spi at all. It
// still exists, so the command must update it rather than try to create it.
func TestSecretCreateRotatesExistingSecretWithoutSpi(t *testing.T) {
	k := runSecretCreate(t, ipsecSecret(`{"aeadKeyName":"rfc4106(gcm(aes))","aeadKey":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","length":128}`))
	if key := storedKey(t, k); key.Spi != 1 {
		t.Fatalf("expected spi 1 after rotating a secret without spi, got %d", key.Spi)
	}
}
