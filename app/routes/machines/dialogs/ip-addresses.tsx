import { useEffect, useRef, useState } from "react";
import { useFetcher } from "react-router";

import Dialog, { DialogPanel } from "~/components/dialog";
import Input from "~/components/input";
import Text from "~/components/text";
import Title from "~/components/title";
import type { Machine } from "~/types";

interface IPAddressesProps {
  machine: Machine;
  isOpen: boolean;
  setIsOpen: (isOpen: boolean) => void;
}

function addressesFor(machine: Machine) {
  return {
    ipv4: machine.ipAddresses.find((address) => !address.includes(":")) ?? "",
    ipv6: machine.ipAddresses.find((address) => address.includes(":")) ?? "",
  };
}

export default function IPAddresses({ machine, isOpen, setIsOpen }: IPAddressesProps) {
  const fetcher = useFetcher();
  const submittingRef = useRef(false);
  const initial = addressesFor(machine);
  const [ipv4, setIPv4] = useState(initial.ipv4);
  const [ipv6, setIPv6] = useState(initial.ipv6);
  const error = fetcher.data && !fetcher.data.success ? fetcher.data.error : null;
  const canSubmit = fetcher.state === "idle" && (ipv4.trim() !== "" || ipv6.trim() !== "");

  useEffect(() => {
    if (fetcher.data?.success) {
      submittingRef.current = false;
      setIsOpen(false);
    }

    if (fetcher.state === "idle" && fetcher.data && !fetcher.data.success) {
      submittingRef.current = false;
    }
  }, [fetcher.data, fetcher.state]);

  useEffect(() => {
    if (isOpen) {
      const addresses = addressesFor(machine);
      setIPv4(addresses.ipv4);
      setIPv6(addresses.ipv6);
    }
  }, [isOpen, machine]);

  return (
    <Dialog
      isOpen={isOpen}
      onOpenChange={(open) => {
        if (!open && submittingRef.current) return;
        setIsOpen(open);
      }}
    >
      <DialogPanel
        isDisabled={!canSubmit}
        onSubmit={(event) => {
          event.preventDefault();
          submittingRef.current = true;
          const form = new FormData();
          form.set("action_id", "update_ips");
          form.set("node_id", machine.id);
          form.set("ipv4", ipv4.trim());
          form.set("ipv6", ipv6.trim());
          fetcher.submit(form, { method: "POST" });
        }}
      >
        <Title>Edit IP addresses for {machine.givenName}</Title>
        <Text>
          Assign an available address from the IPv4 or IPv6 prefixes configured in Headscale.
          Leaving a field empty keeps that address family unchanged.
        </Text>
        {error ? (
          <p className="rounded-lg bg-red-50 p-3 text-sm text-red-700 dark:bg-red-900/20 dark:text-red-400">
            {error}
          </p>
        ) : null}
        <Input
          label="IPv4 address"
          placeholder="100.64.20.30"
          value={ipv4}
          onChange={setIPv4}
          autoComplete="off"
          spellCheck={false}
        />
        <Input
          label="IPv6 address"
          placeholder="fd7a:115c:a1e0::1234"
          value={ipv6}
          onChange={setIPv6}
          autoComplete="off"
          spellCheck={false}
        />
      </DialogPanel>
    </Dialog>
  );
}
