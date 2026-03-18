package topic

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestNewBroadcaster_NilTopics(t *testing.T) {
	_, err := NewBroadcaster(nil, &BroadcasterConfig{})
	require.Error(t, err)
	require.Contains(t, err.Error(), "at least 1 topic required")
}

func TestNewBroadcaster_InvalidTopicPrefix(t *testing.T) {
	_, err := NewBroadcaster([]string{"bad_topic"}, &BroadcasterConfig{})
	require.Error(t, err)
	require.Contains(t, err.Error(), "must start with 'tm_'")
}

func TestNewBroadcaster_ValidTopics(t *testing.T) {
	b, err := NewBroadcaster([]string{"tm_test"}, &BroadcasterConfig{})
	require.NoError(t, err)
	require.NotNil(t, b)
	require.Equal(t, []string{"tm_test"}, b.Topics)
}

func TestNewBroadcaster_MultipleValidTopics(t *testing.T) {
	topics := []string{"tm_foo", "tm_bar", "tm_baz"}
	b, err := NewBroadcaster(topics, &BroadcasterConfig{})
	require.NoError(t, err)
	require.Equal(t, topics, b.Topics)
}

func TestNewBroadcaster_MixedValidInvalidTopics(t *testing.T) {
	_, err := NewBroadcaster([]string{"tm_good", "bad_topic"}, &BroadcasterConfig{})
	require.Error(t, err)
}

func TestNewBroadcaster_DefaultAckFromAny(t *testing.T) {
	b, err := NewBroadcaster([]string{"tm_test"}, &BroadcasterConfig{})
	require.NoError(t, err)
	// Default AckFromAll should be RequireAckNone, AckFromAny should be RequireAckAll.
	require.Equal(t, RequireAckNone, b.AckFromAll.RequireAck)
	require.Equal(t, RequireAckAll, b.AckFromAny.RequireAck)
}

func TestNewBroadcaster_CustomAckFromAll(t *testing.T) {
	ack := &AckFrom{RequireAck: RequireAckAny, Topics: []string{"tm_test"}}
	b, err := NewBroadcaster([]string{"tm_test"}, &BroadcasterConfig{
		AckFromAll: ack,
	})
	require.NoError(t, err)
	require.Equal(t, RequireAckAny, b.AckFromAll.RequireAck)
}

func TestNewBroadcaster_CustomAckFromAny(t *testing.T) {
	ack := &AckFrom{RequireAck: RequireAckSome, Topics: []string{"tm_test"}}
	b, err := NewBroadcaster([]string{"tm_test"}, &BroadcasterConfig{
		AckFromAny: ack,
	})
	require.NoError(t, err)
	require.Equal(t, RequireAckSome, b.AckFromAny.RequireAck)
}

func TestNewBroadcaster_CustomAckFromHost(t *testing.T) {
	hostAck := map[string]AckFrom{
		"https://host.example.com": {RequireAck: RequireAckAll},
	}
	b, err := NewBroadcaster([]string{"tm_test"}, &BroadcasterConfig{
		AckFromHost: hostAck,
	})
	require.NoError(t, err)
	require.Equal(t, hostAck, b.AckFromHost)
}

func TestNewBroadcaster_DefaultHostOverrideMap(t *testing.T) {
	b, err := NewBroadcaster([]string{"tm_test"}, &BroadcasterConfig{})
	require.NoError(t, err)
	require.NotNil(t, b.AckFromHost)
}

// --- checkAcknowledgmentFromAllHosts ---

func TestCheckAcknowledgmentFromAllHosts_RequireAll_AllPresent(t *testing.T) {
	b := &Broadcaster{Topics: []string{"tm_a", "tm_b"}}
	hostAcks := map[string]map[string]struct{}{
		"host1": {"tm_a": {}, "tm_b": {}},
		"host2": {"tm_a": {}, "tm_b": {}},
	}
	require.True(t, b.checkAcknowledgmentFromAllHosts(hostAcks, []string{"tm_a", "tm_b"}, RequireAckAll))
}

func TestCheckAcknowledgmentFromAllHosts_RequireAll_OneMissing(t *testing.T) {
	b := &Broadcaster{}
	hostAcks := map[string]map[string]struct{}{
		"host1": {"tm_a": {}}, // missing tm_b
	}
	require.False(t, b.checkAcknowledgmentFromAllHosts(hostAcks, []string{"tm_a", "tm_b"}, RequireAckAll))
}

func TestCheckAcknowledgmentFromAllHosts_RequireAny_OnePresent(t *testing.T) {
	b := &Broadcaster{}
	hostAcks := map[string]map[string]struct{}{
		"host1": {"tm_a": {}},
	}
	require.True(t, b.checkAcknowledgmentFromAllHosts(hostAcks, []string{"tm_a", "tm_b"}, RequireAckAny))
}

func TestCheckAcknowledgmentFromAllHosts_RequireAny_NonePresent(t *testing.T) {
	b := &Broadcaster{}
	hostAcks := map[string]map[string]struct{}{
		"host1": {"tm_other": {}},
	}
	require.False(t, b.checkAcknowledgmentFromAllHosts(hostAcks, []string{"tm_a", "tm_b"}, RequireAckAny))
}

func TestCheckAcknowledgmentFromAllHosts_EmptyHosts(t *testing.T) {
	b := &Broadcaster{}
	hostAcks := map[string]map[string]struct{}{}
	// No hosts to iterate; returns true (vacuously satisfied).
	require.True(t, b.checkAcknowledgmentFromAllHosts(hostAcks, []string{"tm_a"}, RequireAckAll))
}

// --- checkAcknowledgmentFromAnyHost ---

func TestCheckAcknowledgmentFromAnyHost_RequireAll_AllPresent(t *testing.T) {
	b := &Broadcaster{}
	hostAcks := map[string]map[string]struct{}{
		"host1": {"tm_a": {}, "tm_b": {}},
	}
	require.True(t, b.checkAcknowledgmentFromAnyHost(hostAcks, []string{"tm_a", "tm_b"}, RequireAckAll))
}

func TestCheckAcknowledgmentFromAnyHost_RequireAll_Missing(t *testing.T) {
	b := &Broadcaster{}
	hostAcks := map[string]map[string]struct{}{
		"host1": {"tm_a": {}}, // tm_b missing
	}
	require.False(t, b.checkAcknowledgmentFromAnyHost(hostAcks, []string{"tm_a", "tm_b"}, RequireAckAll))
}

func TestCheckAcknowledgmentFromAnyHost_RequireAny_OnePresent(t *testing.T) {
	b := &Broadcaster{}
	hostAcks := map[string]map[string]struct{}{
		"host1": {"tm_a": {}},
	}
	require.True(t, b.checkAcknowledgmentFromAnyHost(hostAcks, []string{"tm_a", "tm_b"}, RequireAckAny))
}

func TestCheckAcknowledgmentFromAnyHost_RequireAny_NonePresent(t *testing.T) {
	b := &Broadcaster{}
	hostAcks := map[string]map[string]struct{}{
		"host1": {"tm_other": {}},
	}
	require.False(t, b.checkAcknowledgmentFromAnyHost(hostAcks, []string{"tm_a"}, RequireAckAny))
}

func TestCheckAcknowledgmentFromAnyHost_EmptyHosts(t *testing.T) {
	b := &Broadcaster{}
	hostAcks := map[string]map[string]struct{}{}
	// No hosts; no host satisfies any requirement.
	require.False(t, b.checkAcknowledgmentFromAnyHost(hostAcks, []string{"tm_a"}, RequireAckAll))
}

// --- checkAcknowledgmentFromSpecificHosts ---

func TestCheckAcknowledgmentFromSpecificHosts_HostMissing(t *testing.T) {
	b := &Broadcaster{Topics: []string{"tm_a"}}
	hostAcks := map[string]map[string]struct{}{
		"host1": {"tm_a": {}},
	}
	requirements := map[string]AckFrom{
		"host2": {RequireAck: RequireAckAll}, // host2 not in hostAcks
	}
	require.False(t, b.checkAcknowledgmentFromSpecificHosts(hostAcks, requirements))
}

func TestCheckAcknowledgmentFromSpecificHosts_RequireAll_Satisfied(t *testing.T) {
	b := &Broadcaster{Topics: []string{"tm_a", "tm_b"}}
	hostAcks := map[string]map[string]struct{}{
		"host1": {"tm_a": {}, "tm_b": {}},
	}
	requirements := map[string]AckFrom{
		"host1": {RequireAck: RequireAckAll},
	}
	require.True(t, b.checkAcknowledgmentFromSpecificHosts(hostAcks, requirements))
}

func TestCheckAcknowledgmentFromSpecificHosts_RequireAll_NotSatisfied(t *testing.T) {
	b := &Broadcaster{Topics: []string{"tm_a", "tm_b"}}
	hostAcks := map[string]map[string]struct{}{
		"host1": {"tm_a": {}}, // tm_b missing
	}
	requirements := map[string]AckFrom{
		"host1": {RequireAck: RequireAckAll},
	}
	require.False(t, b.checkAcknowledgmentFromSpecificHosts(hostAcks, requirements))
}

func TestCheckAcknowledgmentFromSpecificHosts_RequireAny_Satisfied(t *testing.T) {
	b := &Broadcaster{Topics: []string{"tm_a", "tm_b"}}
	hostAcks := map[string]map[string]struct{}{
		"host1": {"tm_a": {}},
	}
	requirements := map[string]AckFrom{
		"host1": {RequireAck: RequireAckAny},
	}
	require.True(t, b.checkAcknowledgmentFromSpecificHosts(hostAcks, requirements))
}

func TestCheckAcknowledgmentFromSpecificHosts_RequireAny_NotSatisfied(t *testing.T) {
	b := &Broadcaster{Topics: []string{"tm_a", "tm_b"}}
	hostAcks := map[string]map[string]struct{}{
		"host1": {"tm_other": {}},
	}
	requirements := map[string]AckFrom{
		"host1": {RequireAck: RequireAckAny},
	}
	require.False(t, b.checkAcknowledgmentFromSpecificHosts(hostAcks, requirements))
}

func TestCheckAcknowledgmentFromSpecificHosts_RequireSome(t *testing.T) {
	b := &Broadcaster{Topics: []string{"tm_a"}}
	hostAcks := map[string]map[string]struct{}{
		"host1": {"tm_specific": {}},
	}
	requirements := map[string]AckFrom{
		"host1": {RequireAck: RequireAckSome, Topics: []string{"tm_specific"}},
	}
	require.True(t, b.checkAcknowledgmentFromSpecificHosts(hostAcks, requirements))
}

func TestCheckAcknowledgmentFromSpecificHosts_RequireNone_Skipped(t *testing.T) {
	b := &Broadcaster{Topics: []string{"tm_a"}}
	hostAcks := map[string]map[string]struct{}{
		"host1": {},
	}
	// RequireAckNone results in the host requirement being skipped (continue).
	requirements := map[string]AckFrom{
		"host1": {RequireAck: RequireAckNone},
	}
	require.True(t, b.checkAcknowledgmentFromSpecificHosts(hostAcks, requirements))
}

func TestCheckAcknowledgmentFromSpecificHosts_EmptyRequirements(t *testing.T) {
	b := &Broadcaster{}
	hostAcks := map[string]map[string]struct{}{}
	require.True(t, b.checkAcknowledgmentFromSpecificHosts(hostAcks, map[string]AckFrom{}))
}
